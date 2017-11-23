// Copyright 2015 CNI authors
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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

type NetConf struct {
	types.NetConf
	VlanId int    `json:"vlanId"`
	MTU    int    `json:"mtu,omitempty"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	if n.VlanId < 0 || n.VlanId > 4094 {
		return nil, "", fmt.Errorf(`invalid VLAN ID %d (must be between 0 and 4095 inclusive)`, n.VlanId)
	}
	return n, n.CNIVersion, nil
}

func setupVF(conf *NetConf, ifName string, netns ns.NetNS) (*current.Interface, error) {
	vf := &current.Interface{}

	// 申请一个可用的Virtual Function
	m, vfIdx, vfDevName, err := allocFreeVF()
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "***********CNI SR-IOV 成功申请%v网卡的第%v个VF, 名称为: %v\n", m.Attrs().Name, vfIdx, vfDevName)

	vfDev, err := netlink.LinkByName(vfDevName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup vf device %q: %v", vfDevName, err)
	}

	if conf.MTU <= 0 {
		conf.MTU = m.Attrs().MTU
	}

	if err = netlink.LinkSetVfHardwareAddr(m, vfIdx, vfDev.Attrs().HardwareAddr); err != nil {
                return nil, fmt.Errorf("failed to set vf %d macaddress: %v", vfIdx, err)
        }

	if err = netlink.LinkSetVfVlan(m, vfIdx, conf.VlanId); err != nil {
                return nil, fmt.Errorf("failed to set vf %d vlan: %v", vfIdx, err)
        }

	if err = netlink.LinkSetUp(vfDev); err != nil {
		return nil, fmt.Errorf("failed to setup vf %d device: %v", vfIdx, err)
	}

	// move VF device to ns
	if err = netlink.LinkSetNsFd(vfDev, int(netns.Fd())); err != nil {
		return nil, fmt.Errorf("failed to move vf %d to netns: %v", vfIdx, err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		err := ip.RenameLink(vfDevName, ifName)
		if err != nil {
			return fmt.Errorf("failed to rename vlan to %q: %v", ifName, err)
		}
		vf.Name = ifName

		// Re-fetch interface to get all properties/attributes
		contVF, err := netlink.LinkByName(vf.Name)
		if err != nil {
			return fmt.Errorf("failed to refetch vlan %q: %v", vf.Name, err)
		}
		vf.Mac = contVF.Attrs().HardwareAddr.String()
		vf.Sandbox = netns.Path()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return vf, nil
}

func allocFreeVF() (netlink.Link, int, string, error) {
	vfIdx := -1
	devName := ""

	// 获取机器可用物理网卡(PF)列表
	links, err := netlink.LinkList()
	if err != nil {
		return nil, -1, "", fmt.Errorf("获取可用物理网卡失败: %v", err)
	}

	for _, link := range links {
		if link.Type() == "device" && link.Attrs().OperState == netlink.OperUp {
			master := link.Attrs().Name

			sriovFile := fmt.Sprintf("/sys/class/net/%s/device/sriov_numvfs", master)
			if _, err := os.Lstat(sriovFile); err != nil {
				return nil, -1, "", fmt.Errorf("failed to open the sriov_numfs of device %q: %v", master, err)
			}

			data, err := ioutil.ReadFile(sriovFile)
			if err != nil {
				return nil, -1, "", fmt.Errorf("failed to read the sriov_numfs of device %q: %v", master, err)
			}

			if len(data) == 0 {
				return nil, -1, "", fmt.Errorf("no data in the file %q", sriovFile)
			}

			sriovNumfs := strings.TrimSpace(string(data))
			vfTotal, err := strconv.Atoi(sriovNumfs)
			if err != nil {
				return nil, -1, "", fmt.Errorf("failed to convert sriov_numfs(byte value) to int of device %q: %v", master, err)
			}

			if vfTotal <= 0 {
				return nil, -1, "", fmt.Errorf("no virtual function in the device %q: %v", master)
			}

			for vf := 0; vf < vfTotal; vf++ {
				devName, err = getVFDeviceName(master, vf)

				// got a free vf
				if err == nil {
					vfIdx = vf
					break
				}
			}

			if vfIdx == -1 {
				return nil, -1, "", fmt.Errorf("can not get a free virtual function in directory %s", master)
			}
			return link, vfIdx, devName, nil
		}
	}
	return nil, vfIdx, devName, fmt.Errorf("该主机无可用物理网卡")
}

func getVFDeviceName(master string, vf int) (string, error) {
	vfDir := fmt.Sprintf("/sys/class/net/%s/device/virtfn%d/net", master, vf)
	if _, err := os.Lstat(vfDir); err != nil {
		return "", fmt.Errorf("failed to open the virtfn%d dir of the device %q: %v", vf, master, err)
	}

	infos, err := ioutil.ReadDir(vfDir)
	if err != nil {
		return "", fmt.Errorf("failed to read the virtfn%d dir of the device %q: %v", vf, master, err)
	}

	if len(infos) != 1 {
		return "", fmt.Errorf("no network device in directory %s", vfDir)
	}
	return infos[0].Name(), nil
}

func releaseVF(conf *NetConf, ifName string, netns ns.NetNS) error {
	initns, err := ns.GetCurrentNS()
	fmt.Fprintf(os.Stderr, "***********CNI SR-IOV releaseVF initns = %v\n", initns)
	if err != nil {
		return fmt.Errorf("failed to get init netns: %v", err)
	}

	// for IPAM in cmdDel
	return netns.Do(func(_ ns.NetNS) error {

		// get VF device
		vfDev, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to lookup device %s: %v", ifName, err)
		}

		// device name in init netns
		index := vfDev.Attrs().Index
		devName := fmt.Sprintf("dev%d", index)
		fmt.Fprintf(os.Stderr, "***********CNI SR-IOV releaseVF index = %v devName = %v vfDev = %v\n", index, devName, vfDev)

		// shutdown VF device
		if err = netlink.LinkSetDown(vfDev); err != nil {
			return fmt.Errorf("failed to down device: %v", err)
		}

		// rename VF device
		err = ip.RenameLink(ifName, devName)
		if err != nil {
			return fmt.Errorf("failed to rename device %s to %s: %v", ifName, devName, err)
		}

		// move VF device to init netns
		if err = netlink.LinkSetNsFd(vfDev, int(initns.Fd())); err != nil {
			return fmt.Errorf("failed to move device %s to init netns: %v", ifName, err)
		}

		return nil
	})
}

func cmdAdd(args *skel.CmdArgs) error {
	fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdAdd args.ContainerID = %v\n", args.ContainerID)
	fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdAdd args.Netns = %v\n", args.Netns)
	fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdAdd args.IfName = %v\n", args.IfName)
	fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdAdd args.Args = %v\n", args.Args)
	fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdAdd args.Path = %v\n", args.Path)
	fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdAdd args.StdinData = %v\n", string(args.StdinData))
	n, cniVersion, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	vfInterface, err := setupVF(n, args.IfName, netns)
	if err != nil {
		return err
	}

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}
	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}
	for _, ipc := range result.IPs {
		// All addresses belong to the vlan interface
		ipc.Interface = current.Int(0)
	}

	result.Interfaces = []*current.Interface{vfInterface}

	err = netns.Do(func(_ ns.NetNS) error {
		return ipam.ConfigureIface(args.IfName, result)
	})
	if err != nil {
		return err
	}

	result.DNS = n.DNS

	fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdAdd result = %v\n", result)
	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdDel args.ContainerID = %v\n", args.ContainerID)
        fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdDel args.Netns = %v\n", args.Netns)
        fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdDel args.IfName = %v\n", args.IfName)
        fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdDel args.Args = %v\n", args.Args)
        fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdDel args.Path = %v\n", args.Path)
        fmt.Fprintf(os.Stderr, "***********CNI SR-IOV cmdDel args.StdinData = %v\n", string(args.StdinData))
	n, _, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	netns, err := ns.GetNS(args.Netns)
        if err != nil {
                return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
        }
        defer netns.Close()


	if err = releaseVF(n, args.IfName, netns); err != nil {
		return err
	}

	err = ipam.ExecDel(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}


	// err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
	// 	// get VF device
        //         vfDev, err := netlink.LinkByName(ifName)
        //         if err != nil {
        //                 return fmt.Errorf("failed to lookup device %s: %v", ifName, err)
        //         }

        //         // device name in init netns
        //         index := vfDev.Attrs().Index
        //         devName := fmt.Sprintf("%s_%d", n.Master, index)

	// 	// shutdown VF device
	// 	if err = netlink.LinkSetDown(vfDev); err != nil {
	// 		return fmt.Errorf("failed to down device: %v", err)
	// 	}

	// 	// rename VF device
	// 	err = ip.RenameLink(ifName, devName)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to rename device %s to %s: %v", ifName, devName, err)
	// 	}

	// 	// move VF device to init netns
	// 	// if err = netlink.LinkSetNsFd(vfDev, int(ns.Fd())); err != nil {
	// 	// 	return fmt.Errorf("failed to move device %s to init netns: %v", ifName, err)
	// 	// }
	// 	_, err = ip.DelLinkByNameAddr(ifName, netlink.FAMILY_V4)
	// 	// FIXME: use ip.ErrLinkNotFound when cni is revendored
	// 	if err != nil && err.Error() == "Link not found" {
	// 		return nil
	// 	}
	// 	return err
	// })

	return err
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
