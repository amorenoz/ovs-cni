// Copyright 2026 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vhostuser

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/testutils"
	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const bridgeName = "test-vhu-br"
const IFNAME = "net1"
const containerID = "vhu-dummy"

var _ = BeforeSuite(func() {
	output, err := exec.Command("ovs-vsctl", "show").CombinedOutput()
	Expect(err).NotTo(HaveOccurred(),
		"Open vSwitch is not available, if you have it installed and running, try to run tests with `sudo -E`: %v",
		string(output))
})

var _ = AfterSuite(func() {
	output, err := exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "Cleanup of the bridge failed: %v", string(output))
})

var _ = Describe("Vhost-User CNI Plugin", func() {
	Context("with OVS bridge", func() {
		//var cacheTmpDir string

		BeforeEach(func() {
			var err error
			//cacheTmpDir, err = os.MkdirTemp("", "ovs-cni-vhu-test*")
			//Expect(err).NotTo(HaveOccurred())
			//utils.SetCacheRootDir(cacheTmpDir)

			output, err := exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName, "--", "add-br", bridgeName).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "Failed to create testing OVS bridge: %v", string(output))
		})

		AfterEach(func() {
			output, err := exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), "Failed to remove testing OVS bridge: %v", string(output))

			//utils.SetCacheRootDir("")
			//Expect(os.RemoveAll(cacheTmpDir)).NotTo(HaveOccurred())
		})

		Context("ADD and DEL with client mode", func() {
			It("should create a dpdkvhostuserclient port and clean up on DEL", func() {
				tmpDir := GinkgoT().TempDir()
				socketPath := filepath.Join(tmpDir, "sock-dir", "vhost.sock")
				devInfoFile := writeDevInfoFile(tmpDir, "client", socketPath)
				conf := vhostUserConf("1.0.0", bridgeName, devInfoFile)

				By("Calling ADD command")
				args := cniArgs(containerID, IFNAME, conf)
				_, _, err := cmdAddWithArgs(args, func() error {
					return CmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Checking that the socket directory was created")
				socketDir := filepath.Dir(socketPath)
				_, err = os.Stat(socketDir)
				Expect(err).NotTo(HaveOccurred())

				By("Checking that the port exists on the bridge")
				expectedPort := portName(containerID, IFNAME)
				brPorts, err := listBridgePorts(bridgeName)
				Expect(err).NotTo(HaveOccurred())
				Expect(brPorts).To(ContainElement(expectedPort))

				By("Checking that the interface type is dpdkvhostuserclient")
				intfType, err := getInterfaceAttribute(expectedPort, "type")
				Expect(err).NotTo(HaveOccurred())
				Expect(intfType).To(Equal("dpdkvhostuserclient"))

				By("Checking that vhost-server-path option is set")
				optPath, err := getInterfaceAttribute(expectedPort, "options:vhost-server-path")
				Expect(err).NotTo(HaveOccurred())
				Expect(optPath).To(Equal(fmt.Sprintf("\"%s\"", socketPath)))

				By("Calling DEL command")
				err = cmdDelWithArgs(args, func() error {
					return CmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Checking that the port was removed from the bridge")
				brPorts, err = listBridgePorts(bridgeName)
				Expect(err).NotTo(HaveOccurred())
				Expect(brPorts).NotTo(ContainElement(expectedPort))

				By("Checking that the socket directory was removed")
				_, err = os.Stat(socketDir)
				Expect(os.IsNotExist(err)).To(BeTrue())
			})
		})

		Context("ADD with VLAN tag", func() {
			It("should create a port with the correct VLAN tag", func() {
				tmpDir := GinkgoT().TempDir()
				socketPath := filepath.Join(tmpDir, "sock-dir", "vhost.sock")
				devInfoFile := writeDevInfoFile(tmpDir, "client", socketPath)
				conf := fmt.Sprintf(`{
					"cniVersion": "1.0.0",
					"name": "mynet",
					"type": "ovs-vhostuser",
					"bridge": "%s",
					"vlan": 100,
					"runtimeConfig": {
						"CNIDeviceInfoFile": "%s"
					}
				}`, bridgeName, devInfoFile)

				args := cniArgs(containerID, IFNAME, conf)
				_, _, err := cmdAddWithArgs(args, func() error {
					return CmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Checking that the port has the correct VLAN tag")
				expectedPort := portName(containerID, IFNAME)
				vlanTag, err := getPortAttribute(expectedPort, "tag")
				Expect(err).NotTo(HaveOccurred())
				Expect(vlanTag).To(Equal("100"))

				By("Cleanup")
				err = cmdDelWithArgs(args, func() error {
					return CmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("ADD returns result", func() {
			It("should return a result with one interface and no IPs", func() {
				tmpDir := GinkgoT().TempDir()
				socketPath := filepath.Join(tmpDir, "sock-dir", "vhost.sock")
				devInfoFile := writeDevInfoFile(tmpDir, "client", socketPath)
				conf := vhostUserConf("1.0.0", bridgeName, devInfoFile)

				args := cniArgs(containerID, IFNAME, conf)
				r, _, err := cmdAddWithArgs(args, func() error {
					return CmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				result, err := current.GetResult(r)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.Interfaces).To(HaveLen(1))
				Expect(result.Interfaces[0].Name).To(Equal(IFNAME))
				Expect(result.Interfaces[0].Sandbox).To(BeEmpty())
				Expect(result.IPs).To(BeEmpty())

				By("Cleanup")
				err = cmdDelWithArgs(args, func() error {
					return CmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("DEL is idempotent", func() {
			It("should not error when called twice", func() {
				tmpDir := GinkgoT().TempDir()
				socketPath := filepath.Join(tmpDir, "sock-dir", "vhost.sock")
				devInfoFile := writeDevInfoFile(tmpDir, "client", socketPath)
				conf := vhostUserConf("1.0.0", bridgeName, devInfoFile)

				args := cniArgs(containerID, IFNAME, conf)
				_, _, err := cmdAddWithArgs(args, func() error {
					return CmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Calling DEL the first time")
				err = cmdDelWithArgs(args, func() error {
					return CmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Calling DEL the second time — should not error")
				err = cmdDelWithArgs(args, func() error {
					return CmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())
			})
		})
	}) // end "with OVS bridge"

	Context("ADD fails without CNIDeviceInfoFile", func() {
		It("should return an error", func() {
			conf := fmt.Sprintf(`{
				"cniVersion": "1.0.0",
				"name": "mynet",
				"type": "ovs-vhostuser",
				"bridge": "%s"
			}`, bridgeName)

			args := cniArgs(containerID, IFNAME, conf)
			_, _, err := cmdAddWithArgs(args, func() error {
				return CmdAdd(args)
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("CNIDeviceInfoFile"))
		})
	})

	Context("ADD fails with missing devinfo file", func() {
		It("should return an error", func() {
			conf := vhostUserConf("1.0.0", bridgeName, "/nonexistent/devinfo.json")

			args := cniArgs(containerID, IFNAME, conf)
			_, _, err := cmdAddWithArgs(args, func() error {
				return CmdAdd(args)
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to read device info file"))
		})
	})

	Context("ADD fails with non-vhost-user devinfo", func() {
		It("should return an error for PCI type", func() {
			tmpDir := GinkgoT().TempDir()
			devInfo := nadv1.DeviceInfo{
				Type:    nadv1.DeviceInfoTypePCI,
				Version: nadv1.DeviceInfoVersion,
				Pci:     &nadv1.PciDevice{PciAddress: "0000:01:00.0"},
			}
			devInfoFile := writeDevInfo(tmpDir, devInfo)
			conf := vhostUserConf("1.0.0", bridgeName, devInfoFile)

			args := cniArgs(containerID, IFNAME, conf)
			_, _, err := cmdAddWithArgs(args, func() error {
				return CmdAdd(args)
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected type"))
		})
	})

	Context("ADD fails without bridge name", func() {
		It("should return an error", func() {
			tmpDir := GinkgoT().TempDir()
			socketPath := filepath.Join(tmpDir, "sock-dir", "vhost.sock")
			devInfoFile := writeDevInfoFile(tmpDir, "client", socketPath)
			conf := fmt.Sprintf(`{
				"cniVersion": "1.0.0",
				"name": "mynet",
				"type": "ovs-vhostuser",
				"runtimeConfig": {
					"CNIDeviceInfoFile": "%s"
				}
			}`, devInfoFile)

			args := cniArgs(containerID, IFNAME, conf)
			_, _, err := cmdAddWithArgs(args, func() error {
				return CmdAdd(args)
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("bridge name is required"))
		})
	})

	Context("ADD fails with invalid vhost-user mode", func() {
		It("should return an error", func() {
			tmpDir := GinkgoT().TempDir()
			socketPath := filepath.Join(tmpDir, "sock-dir", "vhost.sock")
			devInfo := nadv1.DeviceInfo{
				Type:    nadv1.DeviceInfoTypeVHostUser,
				Version: nadv1.DeviceInfoVersion,
				VhostUser: &nadv1.VhostDevice{
					Mode: "invalid",
					Path: socketPath,
				},
			}
			devInfoFile := writeDevInfo(tmpDir, devInfo)
			conf := vhostUserConf("1.0.0", bridgeName, devInfoFile)

			args := cniArgs(containerID, IFNAME, conf)
			_, _, err := cmdAddWithArgs(args, func() error {
				return CmdAdd(args)
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid vhost-user mode"))
		})
	})
})

// --- helpers ---

func writeDevInfoFile(tmpDir, mode, socketPath string) string {
	devInfo := nadv1.DeviceInfo{
		Type:    nadv1.DeviceInfoTypeVHostUser,
		Version: nadv1.DeviceInfoVersion,
		VhostUser: &nadv1.VhostDevice{
			Mode: mode,
			Path: socketPath,
		},
	}
	return writeDevInfo(tmpDir, devInfo)
}

func writeDevInfo(tmpDir string, devInfo nadv1.DeviceInfo) string {
	data, err := json.Marshal(devInfo)
	Expect(err).NotTo(HaveOccurred())
	path := filepath.Join(tmpDir, "devinfo.json")
	err = os.WriteFile(path, data, 0644)
	Expect(err).NotTo(HaveOccurred())
	return path
}

func vhostUserConf(version, bridge, devInfoFile string) string {
	return fmt.Sprintf(`{
		"cniVersion": "%s",
		"name": "mynet",
		"type": "ovs-vhostuser",
		"bridge": "%s",
		"runtimeConfig": {
			"CNIDeviceInfoFile": "%s"
		}
	}`, version, bridge, devInfoFile)
}

func cniArgs(containerID, ifName, conf string) *skel.CmdArgs {
	return &skel.CmdArgs{
		ContainerID: containerID,
		Netns:       "",
		IfName:      ifName,
		StdinData:   []byte(conf),
	}
}

func cmdAddWithArgs(args *skel.CmdArgs, f func() error) (cnitypes.Result, []byte, error) {
	return testutils.CmdAdd(args.Netns, args.ContainerID, args.IfName, args.StdinData, f)
}

func cmdDelWithArgs(args *skel.CmdArgs, f func() error) error {
	return testutils.CmdDel(args.Netns, args.ContainerID, args.IfName, f)
}

func listBridgePorts(brName string) ([]string, error) {
	output, err := exec.Command("ovs-vsctl", "list-ports", brName).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list bridge ports: %v", string(output))
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return []string{}, nil
	}
	return lines, nil
}

func getPortAttribute(portName, attributeName string) (string, error) {
	output, err := exec.Command("ovs-vsctl", "get", "Port", portName, attributeName).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get port attribute: %v", string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

func getInterfaceAttribute(intfName, attributeName string) (string, error) {
	output, err := exec.Command("ovs-vsctl", "get", "Interface", intfName, attributeName).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get interface attribute: %v", string(output))
	}
	return strings.TrimSpace(string(output)), nil
}
