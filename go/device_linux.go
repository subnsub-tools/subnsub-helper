//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

const dmiDir = "/sys/class/dmi/id/"

// readDevice on Linux, in order of what knows best: Android's own properties;
// the firmware's DMI table (every PC, server and cloud VM); the device tree
// (ARM boards, Macs under Asahi); and over whichever answered, what a NAS
// system leaves on disk.
func readDevice() Device {
	if onAndroid() {
		return androidDevice()
	}
	var d Device
	if dmi := readDMI(); dmi != (dmiInfo{}) {
		d = classifyDMI(dmi, cpuHypervisor())
	}
	if d.Vendor == "" && d.Model == "" {
		model, _ := readSmall("/proc/device-tree/model")
		compat, _ := readSmall("/proc/device-tree/compatible")
		if t := classifyDT(model, compat); t != (Device{}) {
			d = t
		}
	}
	if d == (Device{}) {
		if wsl() {
			d = Device{Vendor: "Microsoft", Model: "WSL", Form: formVM}
		} else if cpuHypervisor() {
			d.Form = formVM
		}
	}
	return nasOverlay(d, readNAS())
}

func dmiRead(name string) string {
	v, _ := readSmall(dmiDir + name)
	return strings.TrimSpace(v)
}

func readDMI() dmiInfo {
	return dmiInfo{
		Vendor: dmiRead("sys_vendor"), Product: dmiRead("product_name"),
		Version: dmiRead("product_version"), Family: dmiRead("product_family"),
		Chassis: dmiRead("chassis_type"), ChassisVendor: dmiRead("chassis_vendor"),
		AssetTag:    dmiRead("chassis_asset_tag"),
		BoardVendor: dmiRead("board_vendor"), BoardName: dmiRead("board_name"),
	}
}

// The x86 CPU's "running under a hypervisor" flag, or Xen's own file. ARM has
// no such flag; its VMs are found by their DMI table or device tree.
func cpuHypervisor() bool {
	if _, err := os.Stat("/sys/hypervisor/type"); err == nil {
		if v, _ := readSmall("/sys/hypervisor/type"); strings.TrimSpace(v) != "" {
			return true
		}
	}
	info, _ := readSmall("/proc/cpuinfo")
	for _, line := range strings.Split(info, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "flags" {
			return strings.Contains(" "+v+" ", " hypervisor ")
		}
	}
	return false
}

func wsl() bool {
	v, _ := readSmall("/proc/sys/kernel/osrelease")
	v = strings.ToLower(v)
	return strings.Contains(v, "microsoft") || strings.Contains(v, "wsl")
}

// readNAS looks for the storage systems that say who they are on disk. The
// files are all world-readable configuration; nothing here runs a program.
func readNAS() nasFacts {
	if v, ok := readSmall("/etc.defaults/synoinfo.conf"); ok {
		m := confValue(v, "upnpmodelname")
		if m == "" {
			m, _ = readSmall("/proc/sys/kernel/syno_hw_version")
		}
		return nasFacts{OS: "DSM", Vendor: "Synology", Model: strings.TrimSpace(m)}
	}
	if v, ok := readSmall("/etc/config/uLinux.conf"); ok {
		return nasFacts{OS: "QTS", Vendor: "QNAP", Model: confValue(v, "Model")}
	}
	if _, err := os.Stat("/etc/unraid-version"); err == nil {
		return nasFacts{OS: "Unraid"}
	}
	for _, p := range []string{"/usr/bin/midclt", "/usr/local/bin/midclt"} {
		if _, err := os.Stat(p); err == nil {
			return nasFacts{OS: "TrueNAS"}
		}
	}
	if st, err := os.Stat("/etc/openmediavault"); err == nil && st.IsDir() {
		return nasFacts{OS: "openmediavault"}
	}
	// UGREEN's system names itself in os-release. ASUSTOR and TerraMaster
	// boxes are found by their firmware's vendor instead (nasVendors).
	if v, ok := readSmall("/etc/os-release"); ok {
		if strings.Contains(strings.ToLower(confValue(v, "NAME")+" "+confValue(v, "ID")), "ugos") {
			return nasFacts{OS: "UGOS", Vendor: "UGREEN"}
		}
	}
	return nasFacts{}
}

const androidGetprop = "/system/bin/getprop"

// A phone's maker and model, from the system properties every app may read.
func androidDevice() Device {
	d := Device{Vendor: getprop("ro.product.manufacturer"), Model: getprop("ro.product.model"), Form: formPhone}
	if strings.Contains(getprop("ro.build.characteristics"), "tablet") {
		d.Form = formTablet
	}
	d.Vendor = normVendor(d.Vendor)
	d.Model = trimVendor(devText(d.Model), d.Vendor)
	return d
}

func getprop(name string) string {
	if !usableBinary(androidGetprop) {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, androidGetprop, name)
	cmd.Env = []string{"LC_ALL=C"}
	cmd.WaitDelay = time.Second
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: 4 << 10}
	if cmd.Run() != nil || ctx.Err() != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}
