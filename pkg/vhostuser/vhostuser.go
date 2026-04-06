// Copyright 2026 Red Hat, Inc.
// Copyright 2014 CNI authors
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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"golang.org/x/sys/unix"

	"github.com/k8snetworkplumbingwg/ovs-cni/pkg/config"
	"github.com/k8snetworkplumbingwg/ovs-cni/pkg/ovsdb"
	"github.com/k8snetworkplumbingwg/ovs-cni/pkg/types"
	"github.com/k8snetworkplumbingwg/ovs-cni/pkg/utils"
)

const (
	targetGID   = 107 // This is the group ID of "qemu" user in kubevirt. FIXME: Make it configurable.
	selinuxType = "system_u:object_r:container_file_t:s0"
)

func logCall(command string, args *skel.CmdArgs) {
	log.Printf("CNI %s was called for container ID: %s, network namespace %s, interface name %s, configuration: %s",
		command, args.ContainerID, args.Netns, args.IfName, string(args.StdinData[:]))
}

// loadVhostUserDeviceInfo reads a DeviceInfo file and returns the VhostDevice.
// Returns an error if the file is missing, malformed, or not a vhost-user device.
func loadVhostUserDeviceInfo(devInfoFilePath string) (*nadv1.VhostDevice, error) {
	data, err := os.ReadFile(devInfoFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read device info file %s: %v", devInfoFilePath, err)
	}

	var devInfo nadv1.DeviceInfo
	if err := json.Unmarshal(data, &devInfo); err != nil {
		return nil, fmt.Errorf("failed to parse device info file %s: %v", devInfoFilePath, err)
	}

	if devInfo.Type != nadv1.DeviceInfoTypeVHostUser {
		return nil, fmt.Errorf("device info file %s has unexpected type %q, expected %q",
			devInfoFilePath, devInfo.Type, nadv1.DeviceInfoTypeVHostUser)
	}

	if devInfo.VhostUser == nil {
		return nil, fmt.Errorf("device info file %s has type vhost-user but no vhost-user data", devInfoFilePath)
	}

	if devInfo.VhostUser.Path == "" {
		return nil, fmt.Errorf("device info file %s has empty vhost-user path", devInfoFilePath)
	}

	if devInfo.VhostUser.Mode != nadv1.VhostDeviceModeClient {
		return nil, fmt.Errorf("device info file %s has invalid vhost-user mode %q (only 'client' is supported)", devInfoFilePath, devInfo.VhostUser.Mode)
	}

	return devInfo.VhostUser, nil
}

func createSocketDir(dir string) error {
	oldMask := syscall.Umask(0)
	defer syscall.Umask(oldMask)
	var err error
	if err = os.MkdirAll(dir, 0775); err != nil {
		return fmt.Errorf("failed to create vhost-user socket directory %s: %v", dir, err)
	}

	if err := unix.Chown(dir, -1, targetGID); err != nil {
		return fmt.Errorf("failed to chown %s: %v", dir, err)
	}

	labelBytes := []byte(selinuxType)
	if err := unix.Setxattr(dir, "security.selinux", labelBytes, 0); err != nil {
		log.Printf("failed to setxattr %s: %v", dir, err)
	}

	if _, err := exec.LookPath("setfacl"); err == nil {
		cmd := exec.Command("setfacl", "-R", "-m", "u:openvswitch:rwx", dir)
		if err = cmd.Run(); err != nil {
			if stderr, stderrErr := cmd.CombinedOutput(); stderrErr == nil {
				return fmt.Errorf("failed to set ACL for openvswitch user on %s: %v, stderr: %s", dir, err, string(stderr))
			}
			return fmt.Errorf("failed to set ACL for openvswitch user on %s: %v", dir, err)
		}

		cmd = exec.Command("setfacl", "-R", "-d", "-m", "u:openvswitch:rwx", dir)
		if err = cmd.Run(); err != nil {
			if stderr, stderrErr := cmd.CombinedOutput(); stderrErr == nil {
				return fmt.Errorf("failed to set default ACL for openvswitch user on %s: %v, stderr: %s", dir, err, string(stderr))
			}
			return fmt.Errorf("failed to set default ACL for openvswitch user on %s: %v", dir, err)
		}
	}
	return err
}

// portName derives a deterministic OVS port name from container ID and
// interface name.
func portName(containerID, ifName string) string {
	h := sha256.Sum256([]byte(containerID + "-" + ifName))
	return fmt.Sprintf("vhu%x", h[:6])
}

// CmdAdd creates a DPDK vhost-user port on the OVS bridge.
func CmdAdd(args *skel.CmdArgs) error {
	logCall("ADD", args)

	netconf, err := config.LoadVhostUserConf(args.StdinData)
	if err != nil {
		return err
	}

	if netconf.RuntimeConfig.CNIDeviceInfoFile == "" {
		return fmt.Errorf("CNIDeviceInfoFile runtime config is required")
	}

	vhostDev, err := loadVhostUserDeviceInfo(netconf.RuntimeConfig.CNIDeviceInfoFile)
	if err != nil {
		return err
	}

	if netconf.BrName == "" {
		return fmt.Errorf("bridge name is required for vhost-user ports")
	}

	ovsBridgeDriver, err := ovsdb.NewOvsBridgeDriver(netconf.BrName, netconf.SocketFile)
	if err != nil {
		return err
	}

	if err := ovsBridgeDriver.CleanPorts(); err != nil {
		return err
	}

	portName := portName(args.ContainerID, args.IfName)
	intfType := "dpdkvhostuserclient"
	socketDir := filepath.Dir(vhostDev.Path)

	if err := createSocketDir(socketDir); err != nil {
		return fmt.Errorf("failed to create vhost-user socket directory %s: %v", socketDir, err)
	}

	// Cache for CmdDel
	if err := utils.SaveCache(config.GetCRef(args.ContainerID, args.IfName),
		&types.CachedVhostUserNetConf{Netconf: netconf, VhostUserSocketPath: vhostDev.Path}); err != nil {
		// Clean up socket directory on cache failure
		_ = os.Remove(socketDir)
		return fmt.Errorf("error saving NetConf: %v", err)
	}

	var vlanTag uint
	portType := "trunk"
	if netconf.VlanTag != nil {
		vlanTag = *netconf.VlanTag
		portType = "access"
	}

	options := map[string]string{"vhost-server-path": vhostDev.Path}

	if err := ovsBridgeDriver.CreatePort(portName, args.Netns, args.IfName, "" /* ovnPort */, netconf.OfportRequest,
		vlanTag, nil /* trunks */, portType, intfType, "" /* contPodUid */, options); err != nil {
		// Clean up socket directory on OVS failure
		if rmErr := os.Remove(socketDir); rmErr != nil {
			log.Printf("Failed to clean up vhost-user socket directory %s: %v", socketDir, rmErr)
		}
		return err
	}

	result := &current.Result{
		CNIVersion: netconf.CNIVersion,
		Interfaces: []*current.Interface{
			{
				Name:    args.IfName,
				Sandbox: args.Netns,
			},
		},
	}
	return cnitypes.PrintResult(result, netconf.CNIVersion)
}

// CmdDel removes the DPDK vhost-user port and cleans up the socket directory.
func CmdDel(args *skel.CmdArgs) error {
	logCall("DEL", args)

	cache := &types.CachedVhostUserNetConf{}
	cRef := config.GetCRef(args.ContainerID, args.IfName)
	bytes, err := utils.ReadCache(cRef)
	if err != nil {
		// Cache missing — nothing to clean up (idempotent DEL per CNI spec)
		return nil
	}
	if err = json.Unmarshal(bytes, cache); err != nil {
		return fmt.Errorf("failed to parse cached VhostUserNetConf: %v", err)
	}

	defer func() {
		if err == nil {
			if cleanErr := utils.CleanCache(cRef); cleanErr != nil {
				log.Printf("Failed cleaning up cache: %v", cleanErr)
			}
		}
	}()

	ovsBridgeDriver, err := ovsdb.NewOvsBridgeDriver(cache.Netconf.BrName, cache.Netconf.SocketFile)
	if err != nil {
		return err
	}

	portName := portName(args.ContainerID, args.IfName)
	if delErr := ovsBridgeDriver.DeletePort(portName); delErr != nil {
		// Don't fail — port may already be gone (idempotent DEL per CNI spec)
		log.Printf("Failed to remove vhost-user OVS port %s: %v", portName, delErr)
	}

	if cache.VhostUserSocketPath != "" {
		socketDir := filepath.Dir(cache.VhostUserSocketPath)
		if rmErr := os.Remove(socketDir); rmErr != nil {
			log.Printf("Failed to remove vhost-user socket directory %s: %v", socketDir, rmErr)
		}
	}

	return nil
}

// CmdCheck is not yet implemented for vhost-user ports
func CmdCheck(args *skel.CmdArgs) error {
	logCall("CHECK", args)
	return nil
}
