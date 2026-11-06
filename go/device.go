package main

// What the machine IS, as opposed to what it runs: a MacBook or a Mac mini, a
// Synology or a QNAP, a Raspberry Pi, a ThinkPad, a cloud VM. The page draws
// each machine as itself from this (asked for by the operator on 2026-11-05;
// until then a Mac mini and a MacBook were the same Mac on the page, and a NAS
// was "Linux").
//
// Read once per process: none of it changes while the helper runs, and the one
// expensive read (system_profiler on a Mac) costs most of a second.
//
// What it is NOT is an identity. The vendor and the model name a product line
// that thousands of people own; the serial number, the UUID and the asset tag
// name THIS one, and are never read into a field here (the DMI asset tag is
// compared against a short list of cloud markers and dropped; the serial files
// are root-only on Linux and never opened). Every string goes through
// devText, which keeps it short and printable, and the page shows nothing it
// was not sent.

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

type Device struct {
	Vendor string `json:"vendor,omitempty"` // "Apple", "Synology", "Lenovo"
	Model  string `json:"model,omitempty"`  // "Mac mini", "DS920+", "ThinkPad X1 Carbon Gen 9"
	// Apple's model identifier ("Mac14,12"), the one thing a Mac's model name
	// does not say: which generation it is.
	ID   string `json:"id,omitempty"`
	Form string `json:"form,omitempty"` // one of the form* names below
	// A storage appliance's own system — DSM, QTS, Unraid, TrueNAS — sent only
	// with form "nas". On a box someone built themselves this is the only
	// brand there is: the board's maker says nothing about what it is for.
	OS string `json:"os,omitempty"`
}

// The shapes the page knows how to draw. A closed set: the relay drops
// anything else.
const (
	formLaptop  = "laptop"
	formDesktop = "desktop"
	formMini    = "mini"
	formAIO     = "aio"
	formServer  = "server"
	formVM      = "vm"
	formNAS     = "nas"
	formBoard   = "board"
	formPhone   = "phone"
	formTablet  = "tablet"
)

var deviceForms = map[string]bool{
	formLaptop: true, formDesktop: true, formMini: true, formAIO: true, formServer: true,
	formVM: true, formNAS: true, formBoard: true, formPhone: true, formTablet: true,
}

var deviceOnce struct {
	sync.Once
	d *Device
}

// machineDevice is this machine's Device, or nil when nothing about it could
// be read. A panic in a platform reader costs the field and nothing else.
func machineDevice() *Device {
	deviceOnce.Do(func() {
		defer func() { _ = recover() }()
		deviceOnce.d = readDevice().tidy()
	})
	return deviceOnce.d
}

// tidy is the Device as it is sent: every string cleaned, an identifier that
// is not shaped like one dropped, a form outside the set dropped, the OS only
// on a NAS, and nil when nothing is left.
func (d Device) tidy() *Device {
	d.Vendor = devText(d.Vendor)
	d.Model = devText(d.Model)
	if !macIDRe.MatchString(d.ID) {
		d.ID = ""
	}
	if !deviceForms[d.Form] {
		d.Form = ""
	}
	d.OS = devText(d.OS)
	if d.Form != formNAS {
		d.OS = ""
	}
	if d.Model != "" && d.Vendor != "" && strings.EqualFold(d.Model, d.Vendor) {
		d.Model = ""
	}
	if d == (Device{}) {
		return nil
	}
	return &d
}

const devTextMax = 64

// devText is s fit to send: control characters and U+FFFD out, runs of space
// collapsed, cut to devTextMax runes, and "" for the placeholders firmware
// writes where a name should be.
func devText(s string) string {
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if r == utf8.RuneError || r == 0 {
			continue
		}
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			space = b.Len() > 0
			continue
		}
		need := 1
		if space {
			need = 2
		}
		if n+need > devTextMax {
			break
		}
		if space {
			b.WriteByte(' ')
			n++
			space = false
		}
		b.WriteRune(r)
		n++
	}
	out := strings.TrimSpace(b.String())
	if devPlaceholder(out) {
		return ""
	}
	return out
}

var devPlaceholders = map[string]bool{
	"to be filled by o.e.m.": true, "to be filled by oem": true, "o.e.m.": true, "oem": true,
	"system product name": true, "system manufacturer": true, "system version": true,
	"system name": true, "product name": true, "default string": true, "default": true,
	"not applicable": true, "not specified": true, "not available": true, "none": true,
	"unknown": true, "invalid": true, "n/a": true, "na": true, "empty": true, "undefined": true,
	"type1productconfigid": true, "type1family": true, "type2 - board vendor name1": true,
	"base board product name": true, "base board manufacturer": true, "all series": true,
	"chassis manufacturer": true, "chassis version": true, "sku": true, "x.x": true,
	"to be filled by o.e.m": true,
}

// A name firmware fills in when nobody filled it in, or one with no letters
// at all ("0123456789", "1.0", "-").
func devPlaceholder(s string) bool {
	if s == "" || devPlaceholders[strings.ToLower(s)] {
		return true
	}
	for _, r := range s {
		if unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

/* ---------- Apple ---------------------------------------------------------- */

var macIDRe = regexp.MustCompile(`^([A-Za-z]{1,24})(\d{1,3}),(\d{1,3})$`)

// Apple silicon's identifiers say only "Mac": Mac14,12 is a Mac mini and
// Mac14,2 a MacBook Air. system_profiler names the model, and is asked first;
// this is for when it cannot be run. Every identifier from the M1 Max Mac
// Studio to the M4 machines; anything newer is Apple with no model, which the
// page draws as a Mac.
var macModels = map[string]string{
	"13,1": "Mac Studio", "13,2": "Mac Studio",
	"14,2": "MacBook Air", "14,15": "MacBook Air",
	"14,3": "Mac mini", "14,12": "Mac mini",
	"14,5": "MacBook Pro", "14,6": "MacBook Pro", "14,7": "MacBook Pro", "14,9": "MacBook Pro", "14,10": "MacBook Pro",
	"14,8":  "Mac Pro",
	"14,13": "Mac Studio", "14,14": "Mac Studio",
	"15,3": "MacBook Pro", "15,6": "MacBook Pro", "15,7": "MacBook Pro", "15,8": "MacBook Pro",
	"15,9": "MacBook Pro", "15,10": "MacBook Pro", "15,11": "MacBook Pro",
	"15,4": "iMac", "15,5": "iMac",
	"15,12": "MacBook Air", "15,13": "MacBook Air",
	"15,14": "Mac Studio",
	"16,1":  "MacBook Pro", "16,5": "MacBook Pro", "16,6": "MacBook Pro", "16,7": "MacBook Pro", "16,8": "MacBook Pro",
	"16,2": "iMac", "16,3": "iMac",
	"16,9":  "Mac Studio",
	"16,10": "Mac mini", "16,11": "Mac mini",
	"16,12": "MacBook Air", "16,13": "MacBook Air",
}

// macFromID is the model an identifier names, from its family word (every
// Intel Mac and the first M1 machines: MacBookPro17,1, Macmini9,1) or the
// table above.
func macFromID(id string) string {
	m := macIDRe.FindStringSubmatch(id)
	if m == nil {
		return ""
	}
	switch m[1] {
	case "MacBookPro":
		return "MacBook Pro"
	case "MacBookAir":
		return "MacBook Air"
	case "MacBook":
		return "MacBook"
	case "Macmini":
		return "Mac mini"
	case "iMac":
		return "iMac"
	case "iMacPro":
		return "iMac Pro"
	case "MacPro":
		return "Mac Pro"
	case "Xserve":
		return "Xserve"
	case "VirtualMac":
		return "Virtual Mac"
	case "Mac":
		return macModels[m[2]+","+m[3]]
	}
	return ""
}

// macForm is the shape a Mac's model name describes.
func macForm(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "macbook"):
		return formLaptop
	case strings.HasPrefix(n, "imac"):
		return formAIO
	case strings.HasPrefix(n, "mac mini"):
		return formMini
	case strings.HasPrefix(n, "mac studio"), strings.HasPrefix(n, "mac pro"):
		return formDesktop
	case strings.HasPrefix(n, "xserve"):
		return formServer
	case strings.Contains(n, "virtual"):
		return formVM
	}
	return ""
}

// macDevice puts a Mac together from system_profiler's model name and the
// identifier, either of which may be missing.
func macDevice(name, id string) Device {
	d := Device{Vendor: "Apple", Model: devText(name), ID: id}
	if d.Model == "" {
		d.Model = macFromID(id)
	}
	d.Form = macForm(d.Model)
	return d
}

// parseSPHardware reads the model name and identifier out of
// `system_profiler -json SPHardwareDataType`. Only those two: the struct has
// no field for the serial number or the hardware UUID printed beside them, so
// they are never held.
func parseSPHardware(out string) (name, id string) {
	var v struct {
		SP []struct {
			Name  string `json:"machine_name"`
			Model string `json:"machine_model"`
		} `json:"SPHardwareDataType"`
	}
	if json.Unmarshal([]byte(out), &v) != nil || len(v.SP) == 0 {
		return "", ""
	}
	return strings.TrimSpace(v.SP[0].Name), strings.TrimSpace(v.SP[0].Model)
}

/* ---------- PCs and servers: the firmware's DMI table ---------------------- */

// The DMI strings Linux exposes world-readable under /sys/class/dmi/id. The
// serial and UUID files beside them are root-only, and not in here.
type dmiInfo struct {
	Vendor, Product, Version, Family string
	Chassis                          string // the SMBIOS chassis type, a number
	ChassisVendor, AssetTag          string
	BoardVendor, BoardName           string
}

// The SMBIOS chassis types, as forms. 1 ("other") and 2 ("unknown") are not
// here: VMs report 1, and saying nothing is the honest reading of either.
var chassisForms = map[string]string{
	"3": formDesktop, "4": formDesktop, "5": formDesktop, "6": formDesktop, "7": formDesktop,
	"15": formMini, "16": formMini, "24": formDesktop, "35": formMini, "36": formMini,
	"8": formLaptop, "9": formLaptop, "10": formLaptop, "14": formLaptop, "31": formLaptop, "32": formLaptop,
	"11": formTablet, "30": formTablet,
	"13": formAIO,
	"17": formServer, "23": formServer, "25": formServer, "28": formServer, "29": formServer,
	"33": formMini, "34": formMini,
}

// Vendors as people say them. Matched on the lowercased firmware string;
// anything not here keeps its own name, with the company suffix cut.
var vendorNames = map[string]string{
	"apple inc.": "Apple", "apple computer, inc.": "Apple",
	"dell inc.": "Dell", "dell computer corporation": "Dell",
	"lenovo": "Lenovo", "hp": "HP", "hewlett-packard": "HP", "hpe": "HPE",
	"asustek computer inc.": "ASUS", "asustek computer inc": "ASUS",
	"micro-star international co., ltd.": "MSI", "micro-star international co., ltd": "MSI",
	"gigabyte technology co., ltd.": "Gigabyte", "acer": "Acer",
	"microsoft corporation": "Microsoft", "intel corporation": "Intel", "intel(r) client systems": "Intel",
	"supermicro": "Supermicro", "super micro computer, inc.": "Supermicro",
	"asrock": "ASRock", "framework": "Framework", "system76": "System76", "razer": "Razer",
	"samsung electronics co., ltd.": "Samsung", "toshiba": "Toshiba", "dynabook inc.": "Dynabook",
	"huawei": "Huawei", "huawei technologies co., ltd.": "Huawei", "honor": "Honor",
	"timi": "Xiaomi", "xiaomi": "Xiaomi", "azw": "Beelink", "beelink": "Beelink",
	"micro computer (hk) tech limited": "Minisforum", "minisforum": "Minisforum",
	"synology inc.": "Synology", "qnap systems, inc.": "QNAP", "qnap": "QNAP",
	"asustor inc.": "ASUSTOR", "terramaster": "TerraMaster", "ugreen": "UGREEN",
	"raspberry pi foundation": "Raspberry Pi", "raspberry pi ltd": "Raspberry Pi",
	"raspberry pi trading ltd": "Raspberry Pi", "google": "Google", "valve": "Valve",
	"fujitsu": "Fujitsu", "fujitsu client computing limited": "Fujitsu", "lg electronics": "LG",
	"panasonic corporation": "Panasonic", "gpd": "GPD", "chuwi": "Chuwi", "zotac": "ZOTAC",
}

var vendorSuffixRe = regexp.MustCompile(`(?i)[,.]?\s+(inc\.?|corporation|corp\.?|co\.,? ?ltd\.?|ltd\.?|limited|gmbh|llc|s\.?a\.?|ag|computer inc\.?)$`)

func normVendor(v string) string {
	v = devText(v)
	if v == "" {
		return ""
	}
	if n, ok := vendorNames[strings.ToLower(v)]; ok {
		return n
	}
	for i := 0; i < 3; i++ {
		c := strings.TrimSpace(vendorSuffixRe.ReplaceAllString(v, ""))
		if c == v || c == "" {
			break
		}
		v = c
	}
	return v
}

// trimVendor drops the vendor from the front of a model that repeats it ("HP
// EliteBook 840 G5" from HP), so the page never says it twice.
func trimVendor(model, vendor string) string {
	if vendor == "" || len(model) <= len(vendor)+1 || !strings.EqualFold(model[:len(vendor)+1], vendor+" ") {
		return model
	}
	return strings.TrimSpace(model[len(vendor)+1:])
}

// Storage appliances, whatever their chassis says.
var nasVendors = map[string]bool{"Synology": true, "QNAP": true, "ASUSTOR": true, "TerraMaster": true, "UGREEN": true}

// cloudOf names the cloud a DMI table belongs to, "" for anything else. The
// asset tag is only ever compared here — clouds put a fixed marker in it, a
// company puts its own inventory number, and the second is not this helper's
// to send.
func cloudOf(d dmiInfo) string {
	v, p, tag := strings.ToLower(d.Vendor), strings.ToLower(d.Product), strings.TrimSpace(d.AssetTag)
	switch {
	case tag == "OracleCloud.com":
		return "Oracle Cloud"
	case tag == "Amazon EC2" || v == "amazon ec2":
		return "Amazon EC2"
	case tag == "7783-7084-3265-9085-8269-3286-77":
		return "Azure"
	case p == "google compute engine":
		return "Google Cloud"
	case v == "digitalocean":
		return "DigitalOcean"
	case v == "hetzner":
		return "Hetzner"
	case v == "vultr":
		return "Vultr"
	case v == "linode" || v == "akamai":
		return "Akamai"
	case v == "alibaba cloud":
		return "Alibaba Cloud"
	case v == "tencent cloud":
		return "Tencent Cloud"
	case v == "scaleway":
		return "Scaleway"
	case strings.HasPrefix(v, "openstack") || strings.HasPrefix(p, "openstack"):
		return "OpenStack"
	}
	return ""
}

// hypervisorOf names the hypervisor a DMI table was written by, "" for real
// hardware.
func hypervisorOf(d dmiInfo) string {
	v, p := strings.ToLower(d.Vendor), strings.ToLower(d.Product)
	switch {
	case v == "innotek gmbh" || p == "virtualbox":
		return "VirtualBox"
	case strings.HasPrefix(v, "vmware") || strings.HasPrefix(p, "vmware"):
		return "VMware"
	case v == "microsoft corporation" && p == "virtual machine":
		return "Hyper-V"
	case strings.HasPrefix(v, "parallels") || strings.HasPrefix(p, "parallels"):
		return "Parallels"
	case v == "xen" || strings.Contains(p, "hvm domu"):
		return "Xen"
	case v == "bhyve":
		return "bhyve"
	case v == "nutanix":
		return "Nutanix"
	case v == "qemu" || strings.Contains(p, "kvm") || strings.Contains(p, "qemu") || v == "bochs" || strings.HasPrefix(p, "standard pc ("):
		return "KVM"
	}
	return ""
}

// classifyDMI turns the firmware's table into a Device. hypervisor is the
// CPU's own "I am virtual" flag, which catches the VMs whose table names
// nothing.
func classifyDMI(d dmiInfo, hypervisor bool) Device {
	hv := hypervisorOf(d)
	if c := cloudOf(d); c != "" {
		// A cloud also rents whole machines: EC2's *.metal instances, and
		// Oracle's bare metal, which carries the cloud's asset tag over a
		// real server's table and no hypervisor.
		form := formVM
		if strings.Contains(strings.ToLower(d.Product), "metal") || (c == "Oracle Cloud" && hv == "" && !hypervisor) {
			form = formServer
		}
		return Device{Vendor: c, Form: form}
	}
	if hv != "" {
		return Device{Vendor: hv, Form: formVM}
	}
	// The board's fields stand in only for the ones the firmware left
	// empty: a product name it did write is the machine's, not the board's.
	vendor := normVendor(d.Vendor)
	product, board := devText(d.Product), false
	if vendor == "" {
		vendor = normVendor(d.BoardVendor)
	}
	if product == "" && devText(d.BoardName) != "" && (devText(d.Vendor) == "" || normVendor(d.Vendor) == normVendor(d.BoardVendor)) {
		product, board = devText(d.BoardName), true
	}
	if vendor == "Apple" {
		dev := macDevice("", product)
		if dev.Model == "" {
			dev.Model, dev.Form = product, macForm(product)
		}
		return dev
	}
	model := product
	// Lenovo writes its machine-type code in product_name ("20XW0026US") and
	// the name a person would say in product_version.
	if vendor == "Lenovo" {
		if v := devText(d.Version); v != "" {
			model = v
		} else if f := devText(d.Family); f != "" {
			model = f
		}
	}
	if model == "" && !board {
		model = devText(d.Family)
	}
	model = trimVendor(model, vendor)

	form := chassisForms[strings.TrimSpace(d.Chassis)]
	lm := strings.ToLower(model)
	switch {
	case nasVendors[vendor]:
		form = formNAS
	case vendor == "Raspberry Pi":
		form = formBoard
	case strings.HasPrefix(lm, "nuc") || strings.Contains(lm, " nuc"):
		form = formMini
	case form == "" && (strings.HasPrefix(lm, "poweredge") || strings.HasPrefix(lm, "proliant") || vendor == "Supermicro"):
		form = formServer
	case form == "" && hypervisor:
		form = formVM
	}
	if board && form == "" && (vendor != "" || model != "") {
		// A board's own name says what it is plugged into, not what the box
		// around it looks like.
		form = formDesktop
	}
	return Device{Vendor: vendor, Model: model, Form: form}
}

/* ---------- ARM boards: the device tree ------------------------------------ */

// Makers whose name opens a board's device-tree model.
var boardVendors = []string{
	"Raspberry Pi", "Radxa", "Hardkernel", "Pine64", "PINE64", "Xunlong", "Orange Pi", "Banana Pi",
	"Khadas", "FriendlyElec", "FriendlyARM", "Libre Computer", "NVIDIA", "BeagleBoard", "Rockchip",
	"Allwinner", "Amlogic", "Firefly", "Seeed", "Turing Machines", "StarFive", "Milk-V", "Sipeed",
}

var dtRevRe = regexp.MustCompile(`\s+Rev\s+[0-9.]+$`)

// classifyDT reads /proc/device-tree/model (and compatible, which is only
// matched, never sent): the board's own name on a Raspberry Pi and its kin,
// the Mac's on a machine running Asahi Linux.
func classifyDT(model, compatible string) Device {
	model = devText(strings.TrimRight(model, "\x00"))
	compat := strings.ToLower(compatible)
	lm := strings.ToLower(model)
	switch {
	case model == "" && compatible == "":
		return Device{}
	case strings.Contains(compat, "linux,dummy-virt") || strings.Contains(lm, "dummy-virt"):
		return Device{Form: formVM}
	case strings.HasPrefix(model, "Apple "):
		return macDevice(strings.TrimPrefix(model, "Apple "), "")
	case strings.HasPrefix(model, "Raspberry Pi") || strings.HasPrefix(compat, "raspberrypi,"):
		return Device{Vendor: "Raspberry Pi", Model: dtRevRe.ReplaceAllString(model, ""), Form: formBoard}
	}
	form := formBoard
	if strings.Contains(lm, "book") || strings.Contains(lm, "thinkpad") || strings.Contains(lm, "laptop") {
		form = formLaptop
	}
	for _, v := range boardVendors {
		if strings.HasPrefix(model, v+" ") {
			return Device{Vendor: v, Model: strings.TrimSpace(model[len(v):]), Form: form}
		}
	}
	return Device{Model: model, Form: form}
}

/* ---------- NAS systems ---------------------------------------------------- */

// nasFacts is what a storage appliance's own system leaves on disk, read by
// the platform file; nasOverlay puts it over what the firmware said.
type nasFacts struct {
	OS, Vendor, Model string
}

func nasOverlay(d Device, n nasFacts) Device {
	if n.OS == "" && n.Vendor == "" {
		return d
	}
	// Even in a VM: TrueNAS on Proxmox with the disks passed through is the
	// NAS its owner has, and the hypervisor under it is a detail.
	d.Form, d.OS = formNAS, n.OS
	if n.Vendor != "" {
		d.Vendor = n.Vendor
		if m := devText(n.Model); m != "" {
			d.Model = m
		}
	}
	return d
}

// confValue is key's value in a shell-style or INI-style config file
// (key="value", key = value), "" when it is not there. Only the first match.
func confValue(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), key) {
			continue
		}
		return strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return ""
}
