package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMacDevice(t *testing.T) {
	cases := []struct {
		name, id        string
		model, form, ID string
	}{
		{"Mac mini", "Mac14,12", "Mac mini", formMini, "Mac14,12"},
		{"MacBook Pro", "Mac15,3", "MacBook Pro", formLaptop, "Mac15,3"},
		{"", "Mac14,2", "MacBook Air", formLaptop, "Mac14,2"},
		{"", "Mac16,10", "Mac mini", formMini, "Mac16,10"},
		{"", "Mac13,1", "Mac Studio", formDesktop, "Mac13,1"},
		{"", "Mac14,8", "Mac Pro", formDesktop, "Mac14,8"},
		{"", "Mac16,3", "iMac", formAIO, "Mac16,3"},
		{"", "MacBookPro16,1", "MacBook Pro", formLaptop, "MacBookPro16,1"},
		{"", "Macmini9,1", "Mac mini", formMini, "Macmini9,1"},
		{"", "iMac21,1", "iMac", formAIO, "iMac21,1"},
		{"", "iMacPro1,1", "iMac Pro", formAIO, "iMacPro1,1"},
		{"", "VirtualMac2,1", "Virtual Mac", formVM, "VirtualMac2,1"},
		// An identifier newer than the table: Apple, no model, no shape.
		{"", "Mac99,1", "", "", "Mac99,1"},
		{"", "", "", "", ""},
		// system_profiler's name wins over the table.
		{"Mac Studio", "Mac14,3", "Mac Studio", formDesktop, "Mac14,3"},
	}
	for _, c := range cases {
		d := macDevice(c.name, c.id).tidy()
		if d == nil || d.Vendor != "Apple" || d.Model != c.model || d.Form != c.form || d.ID != c.ID {
			t.Errorf("macDevice(%q, %q) = %+v, want Apple %q %q %q", c.name, c.id, d, c.model, c.form, c.ID)
		}
	}
}

func TestParseSPHardware(t *testing.T) {
	out := `{
  "SPHardwareDataType" : [
    {
      "_name" : "hardware_overview",
      "chip_type" : "Apple M2 Pro",
      "machine_model" : "Mac14,12",
      "machine_name" : "Mac mini",
      "physical_memory" : "16 GB",
      "platform_UUID" : "0F2D3C4B-1111-2222-3333-444455556666",
      "serial_number" : "C02XK1ABCDEF"
    }
  ]
}`
	name, id := parseSPHardware(out)
	if name != "Mac mini" || id != "Mac14,12" {
		t.Fatalf("parseSPHardware = %q, %q", name, id)
	}
	for _, bad := range []string{"", "not json", `{"SPHardwareDataType":[]}`} {
		if n, i := parseSPHardware(bad); n != "" || i != "" {
			t.Errorf("parseSPHardware(%q) = %q, %q, want nothing", bad, n, i)
		}
	}
}

// Nothing that names one unit gets through: the serial and UUID printed next
// to the model are never held, and a DMI asset tag is only compared.
func TestDeviceCarriesNoSerial(t *testing.T) {
	out := `{"SPHardwareDataType":[{"machine_name":"MacBook Air","machine_model":"Mac14,2","serial_number":"C02XK1ABCDEF","platform_UUID":"0F2D3C4B-1111-2222-3333-444455556666"}]}`
	n, id := parseSPHardware(out)
	blob, _ := json.Marshal(macDevice(n, id).tidy())
	for _, s := range []string{"C02XK1ABCDEF", "0F2D3C4B"} {
		if strings.Contains(string(blob), s) {
			t.Errorf("device leaked %q: %s", s, blob)
		}
	}
	blob, _ = json.Marshal(classifyDMI(dmiInfo{Vendor: "Dell Inc.", Product: "OptiPlex 7090", Chassis: "3", AssetTag: "ACME-IT-004211"}, false).tidy())
	if strings.Contains(string(blob), "ACME") {
		t.Errorf("device leaked the asset tag: %s", blob)
	}
	var keys map[string]any
	_ = json.Unmarshal(blob, &keys)
	for k := range keys {
		switch k {
		case "vendor", "model", "id", "form", "os":
		default:
			t.Errorf("unexpected device key %q", k)
		}
	}
}

func TestClassifyDMI(t *testing.T) {
	cases := []struct {
		in                  dmiInfo
		hyper               bool
		vendor, model, form string
	}{
		// This repository's own production host.
		{dmiInfo{Vendor: "QEMU", Product: "KVM Virtual Machine", Version: "virt-4.2", Chassis: "1", ChassisVendor: "QEMU", AssetTag: "OracleCloud.com"}, false, "Oracle Cloud", "", formVM},
		{dmiInfo{Vendor: "Amazon EC2", Product: "m5.large", Chassis: "1", AssetTag: "Amazon EC2"}, true, "Amazon EC2", "", formVM},
		{dmiInfo{Vendor: "Microsoft Corporation", Product: "Virtual Machine", Chassis: "3", AssetTag: "7783-7084-3265-9085-8269-3286-77"}, true, "Azure", "", formVM},
		{dmiInfo{Vendor: "Microsoft Corporation", Product: "Virtual Machine", Chassis: "3"}, true, "Hyper-V", "", formVM},
		{dmiInfo{Vendor: "Google", Product: "Google Compute Engine", Chassis: "1"}, true, "Google Cloud", "", formVM},
		{dmiInfo{Vendor: "QEMU", Product: "Standard PC (Q35 + ICH9, 2009)", Chassis: "1"}, true, "KVM", "", formVM},
		{dmiInfo{Vendor: "innotek GmbH", Product: "VirtualBox", Chassis: "1"}, true, "VirtualBox", "", formVM},
		{dmiInfo{Vendor: "VMware, Inc.", Product: "VMware Virtual Platform", Chassis: "1"}, true, "VMware", "", formVM},
		{dmiInfo{Vendor: "Hetzner", Product: "vServer", Chassis: "1"}, true, "Hetzner", "", formVM},
		// Clouds rent whole machines too.
		{dmiInfo{Vendor: "Amazon EC2", Product: "i3.metal", Chassis: "1", AssetTag: "Amazon EC2"}, false, "Amazon EC2", "", formServer},
		{dmiInfo{Vendor: "Oracle Corporation", Product: "ORACLE SERVER X9-2c", Chassis: "23", AssetTag: "OracleCloud.com"}, false, "Oracle Cloud", "", formServer},
		// Graviton: no hypervisor flag on ARM, still a VM.
		{dmiInfo{Vendor: "Amazon EC2", Product: "c7g.large", Chassis: "1", AssetTag: "Amazon EC2"}, false, "Amazon EC2", "", formVM},
		// A VM whose table names nothing is still a VM.
		{dmiInfo{Vendor: "Some Host", Product: "Cloud Box", Chassis: "1"}, true, "Some Host", "Cloud Box", formVM},

		{dmiInfo{Vendor: "LENOVO", Product: "20XW0026US", Version: "ThinkPad X1 Carbon Gen 9", Family: "ThinkPad X1 Carbon Gen 9", Chassis: "10"}, false, "Lenovo", "ThinkPad X1 Carbon Gen 9", formLaptop},
		{dmiInfo{Vendor: "LENOVO", Product: "10RRS00F00", Version: "ThinkCentre M720q", Chassis: "35"}, false, "Lenovo", "ThinkCentre M720q", formMini},
		{dmiInfo{Vendor: "Dell Inc.", Product: "XPS 13 9310", Chassis: "10"}, false, "Dell", "XPS 13 9310", formLaptop},
		{dmiInfo{Vendor: "HP", Product: "HP EliteBook 840 G5", Chassis: "10"}, false, "HP", "EliteBook 840 G5", formLaptop},
		{dmiInfo{Vendor: "Dell Inc.", Product: "PowerEdge R740", Chassis: "23"}, false, "Dell", "PowerEdge R740", formServer},
		{dmiInfo{Vendor: "Supermicro", Product: "Super Server", Chassis: "1"}, false, "Supermicro", "Super Server", formServer},
		{dmiInfo{Vendor: "Intel(R) Client Systems", Product: "NUC11PAHi5", Chassis: "3"}, false, "Intel", "NUC11PAHi5", formMini},
		{dmiInfo{Vendor: "Apple Inc.", Product: "MacBookPro11,3", Chassis: "10"}, false, "Apple", "MacBook Pro", formLaptop},
		{dmiInfo{Vendor: "Apple Inc.", Product: "Macmini8,1", Chassis: "16"}, false, "Apple", "Mac mini", formMini},
		{dmiInfo{Vendor: "Apple Inc.", Product: "Apple Virtualization Generic Platform", Chassis: "1"}, false, "Apple", "Apple Virtualization Generic Platform", formVM},
		{dmiInfo{Vendor: "Synology Inc.", Product: "DS920+", Chassis: "3"}, false, "Synology", "DS920+", formNAS},
		{dmiInfo{Vendor: "Microsoft Corporation", Product: "Surface Pro 7", Chassis: "9"}, false, "Microsoft", "Surface Pro 7", formLaptop},
		{dmiInfo{Vendor: "TIMI", Product: "RedmiBook Pro 15", Chassis: "10"}, false, "Xiaomi", "RedmiBook Pro 15", formLaptop},
		{dmiInfo{Vendor: "Framework", Product: "Laptop (13th Gen Intel Core)", Chassis: "10"}, false, "Framework", "Laptop (13th Gen Intel Core)", formLaptop},
		{dmiInfo{Vendor: "Gigabyte Technology Co., Ltd.", Product: "B550 AORUS ELITE", Chassis: "3"}, false, "Gigabyte", "B550 AORUS ELITE", formDesktop},
		{dmiInfo{Vendor: "Acme Widgets Inc.", Product: "Box 3000", Chassis: "13"}, false, "Acme Widgets", "Box 3000", formAIO},
		// A home-built PC: the firmware's own fields are placeholders, the
		// board's are real.
		{dmiInfo{Vendor: "To Be Filled By O.E.M.", Product: "To Be Filled By O.E.M.", Chassis: "3", BoardVendor: "ASUSTeK COMPUTER INC.", BoardName: "ROG STRIX B550-F GAMING"}, false, "ASUS", "ROG STRIX B550-F GAMING", formDesktop},
		{dmiInfo{Vendor: "System manufacturer", Product: "System Product Name", Chassis: "1", BoardVendor: "ASRock", BoardName: "B450M Pro4"}, false, "ASRock", "B450M Pro4", formDesktop},
		{dmiInfo{Vendor: "Default string", Product: "Default string", Chassis: "2"}, false, "", "", ""},
		// No vendor, but a product name: the product stays, the vendor comes
		// from the board.
		{dmiInfo{Vendor: "To Be Filled By O.E.M.", Product: "Mini PC X1", Chassis: "35", BoardVendor: "AZW", BoardName: "SER"}, false, "Beelink", "Mini PC X1", formMini},
		{dmiInfo{Vendor: "Default string", Product: "Mystery Box", Chassis: "3"}, false, "", "Mystery Box", formDesktop},
	}
	for _, c := range cases {
		got := classifyDMI(c.in, c.hyper)
		d := got.tidy()
		if d == nil {
			d = &Device{}
		}
		if d.Vendor != c.vendor || d.Model != c.model || d.Form != c.form {
			t.Errorf("classifyDMI(%+v) = %+v, want %q %q %q", c.in, d, c.vendor, c.model, c.form)
		}
	}
}

func TestClassifyDT(t *testing.T) {
	cases := []struct {
		model, compat      string
		vendor, name, form string
	}{
		{"Raspberry Pi 4 Model B Rev 1.4\x00", "raspberrypi,4-model-b\x00brcm,bcm2711\x00", "Raspberry Pi", "Raspberry Pi 4 Model B", formBoard},
		{"Raspberry Pi 5 Model B Rev 1.0\x00", "", "Raspberry Pi", "Raspberry Pi 5 Model B", formBoard},
		{"Raspberry Pi Compute Module 4 Rev 1.1\x00", "", "Raspberry Pi", "Raspberry Pi Compute Module 4", formBoard},
		{"Radxa ROCK 5B\x00", "radxa,rock-5b\x00rockchip,rk3588\x00", "Radxa", "ROCK 5B", formBoard},
		{"Pine64 Pinebook Pro\x00", "", "Pine64", "Pinebook Pro", formLaptop},
		{"Apple MacBook Air (M1, 2020)\x00", "apple,j313\x00apple,t8103\x00", "Apple", "MacBook Air (M1, 2020)", formLaptop},
		{"Apple Mac mini (M2, 2023)\x00", "", "Apple", "Mac mini (M2, 2023)", formMini},
		{"linux,dummy-virt\x00", "linux,dummy-virt\x00", "", "", formVM},
		{"Some Custom Board\x00", "", "", "Some Custom Board", formBoard},
		{"", "", "", "", ""},
	}
	for _, c := range cases {
		d := classifyDT(c.model, c.compat).tidy()
		if d == nil {
			d = &Device{}
		}
		if d.Vendor != c.vendor || d.Model != c.name || d.Form != c.form {
			t.Errorf("classifyDT(%q) = %+v, want %q %q %q", c.model, d, c.vendor, c.name, c.form)
		}
	}
}

func TestNASOverlay(t *testing.T) {
	pc := Device{Vendor: "ASRock", Model: "B550M Pro4", Form: formDesktop}
	if d := nasOverlay(pc, nasFacts{OS: "Unraid"}).tidy(); d.Form != formNAS || d.OS != "Unraid" || d.Vendor != "ASRock" {
		t.Errorf("Unraid on a PC = %+v", d)
	}
	vm := Device{Vendor: "KVM", Form: formVM}
	if d := nasOverlay(vm, nasFacts{OS: "TrueNAS"}).tidy(); d.Form != formNAS || d.OS != "TrueNAS" {
		t.Errorf("TrueNAS in a VM = %+v", d)
	}
	if d := nasOverlay(Device{}, nasFacts{OS: "DSM", Vendor: "Synology", Model: "DS220+\n"}).tidy(); d.Vendor != "Synology" || d.Model != "DS220+" || d.Form != formNAS || d.OS != "DSM" {
		t.Errorf("DSM = %+v", d)
	}
	if d := nasOverlay(pc, nasFacts{}); d != pc {
		t.Errorf("no NAS changed the device: %+v", d)
	}
	// The OS is only ever sent with a NAS.
	if d := (Device{Vendor: "Dell", Form: formLaptop, OS: "DSM"}).tidy(); d.OS != "" {
		t.Errorf("OS kept off a NAS: %+v", d)
	}
}

func TestConfValue(t *testing.T) {
	syno := "unique=\"synology_geminilake_920+\"\nupnpmodelname=\"DS920+\"\nsupportphoto=\"yes\"\n"
	if v := confValue(syno, "upnpmodelname"); v != "DS920+" {
		t.Errorf("synoinfo upnpmodelname = %q", v)
	}
	ini := "[System]\nModel = TS-453D\nVersion = 5.1.0\n"
	if v := confValue(ini, "Model"); v != "TS-453D" {
		t.Errorf("uLinux Model = %q", v)
	}
	if v := confValue(ini, "Missing"); v != "" {
		t.Errorf("missing key = %q", v)
	}
}

func TestDevText(t *testing.T) {
	cases := map[string]string{
		"  Mac   mini \n":              "Mac mini",
		"To Be Filled By O.E.M.":       "",
		"0123456789":                   "",
		"Default string":               "",
		"DS920+":                       "DS920+",
		"bad\x00\x01name\uFFFD":        "bad name",
		strings.Repeat("x", 200):       strings.Repeat("x", devTextMax),
		"ThinkPad\tX1\r\nCarbon":       "ThinkPad X1 Carbon",
		strings.Repeat("x", 63) + " y": strings.Repeat("x", 63),
	}
	for in, want := range cases {
		if got := devText(in); got != want {
			t.Errorf("devText(%q) = %q, want %q", in, got, want)
		}
	}
	if (Device{}).tidy() != nil {
		t.Error("an empty device is sent")
	}
	if d := (Device{Vendor: "Apple", ID: "../etc", Form: "spaceship"}).tidy(); d.ID != "" || d.Form != "" {
		t.Errorf("bad id/form kept: %+v", d)
	}
}

// What this machine says about itself, printed for whoever runs the tests —
// and held to the same rules as everything else it sends.
func TestMachineDeviceIsTidy(t *testing.T) {
	d := machineDevice()
	t.Logf("this machine: %+v", d)
	if d == nil {
		return
	}
	if d.Form != "" && !deviceForms[d.Form] {
		t.Errorf("form %q is not one of the set", d.Form)
	}
	for _, s := range []string{d.Vendor, d.Model, d.OS} {
		if len([]rune(s)) > devTextMax || devText(s) != s {
			t.Errorf("untidy string %q", s)
		}
	}
}
