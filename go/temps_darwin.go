package main

// The calls into IOKit, and nothing else. mactemps.go says why they are made
// from a child process and what is done with the answers; this file is only
// ever run as `subnsub-helper temps`.
//
// purego rather than cgo: build.sh's binaries are CGO_ENABLED=0 and cross-
// compiled from Linux, and purego reaches a dynamic library from exactly that
// kind of build. Every symbol is looked up before it is called and a missing
// one ends the reading, not the process.

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	iokitPath = "/System/Library/Frameworks/IOKit.framework/IOKit"
	cfPath    = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
	libSystem = "/usr/lib/libSystem.B.dylib"

	smcMaxKeys = 4096 // an Intel Mac has some hundreds
)

// Bind fptr to a symbol, or say it is not there. RegisterLibFunc would panic.
func bindSym(lib uintptr, name string, fptr any) bool {
	p, err := purego.Dlsym(lib, name)
	if err != nil || p == 0 {
		return false
	}
	purego.RegisterFunc(fptr, p)
	return true
}

func openLib(path string) (uintptr, bool) {
	h, err := purego.Dlopen(path, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	return h, err == nil && h != 0
}

// This machine's sensors. Apple Silicon is asked for its HID services, and
// for the SMC's processor and GPU keys when those services do not carry the
// processor (appleRows); an Intel Mac has only the SMC.
func localTemps() []Temp {
	if runtime.GOARCH == "arm64" {
		brand, _ := syscall.Sysctl("machdep.cpu.brand_string")
		if rows := appleRows(hidRows(hidTemps()), appleGen(brand), smcTemps); len(rows) > 0 {
			return rows
		}
	}
	return smcRows(smcTemps())
}

// SMCKeyData_t, eighty bytes, as AppleSMC's user client takes it.
type smcKeyData struct {
	key  uint32
	vers struct {
		major, minor, build, reserved byte
		release                       uint16
	}
	plimit struct {
		version, length uint16
		cpu, gpu, mem   uint32
	}
	keyInfo struct {
		dataSize   uint32
		dataType   uint32
		dataAttrib uint8
	}
	result, status, data8 uint8
	data32                uint32
	bytes                 [32]byte
}

const (
	smcHandleYPCEvent = 2 // the user client's one selector
	smcReadKey        = 5
	smcKeyFromIndex   = 8
	smcKeyInfo        = 9
)

func fourCC(s string) uint32 { return binary.BigEndian.Uint32([]byte(s)) }
func fourCCString(v uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return string(b[:])
}

func smcTemps() map[string]float64 {
	if unsafe.Sizeof(smcKeyData{}) != 80 {
		return nil
	}
	iokit, ok := openLib(iokitPath)
	if !ok {
		return nil
	}
	sys, ok := openLib(libSystem)
	if !ok {
		return nil
	}
	var (
		serviceMatching    func(name string) uintptr
		getMatchingService func(port uint32, matching uintptr) uint32
		serviceOpen        func(service, task, typ uint32, conn *uint32) int32
		serviceClose       func(conn uint32) int32
		objectRelease      func(obj uint32) int32
		callStruct         func(conn, selector uint32, in unsafe.Pointer, inSize uintptr, out unsafe.Pointer, outSize *uintptr) int32
	)
	if !(bindSym(iokit, "IOServiceMatching", &serviceMatching) &&
		bindSym(iokit, "IOServiceGetMatchingService", &getMatchingService) &&
		bindSym(iokit, "IOServiceOpen", &serviceOpen) &&
		bindSym(iokit, "IOServiceClose", &serviceClose) &&
		bindSym(iokit, "IOObjectRelease", &objectRelease) &&
		bindSym(iokit, "IOConnectCallStructMethod", &callStruct)) {
		return nil
	}
	// mach_task_self() is a macro over this variable.
	taskp, err := purego.Dlsym(sys, "mach_task_self_")
	if err != nil || taskp == 0 {
		return nil
	}
	// The address of a variable in a loaded library, not of anything the
	// collector moves; read through a pointer to the uintptr so that vet's
	// rule about uintptr arithmetic has nothing to say about it.
	task := *(*uint32)(*(*unsafe.Pointer)(unsafe.Pointer(&taskp)))

	matching := serviceMatching("AppleSMC")
	if matching == 0 {
		return nil
	}
	// Consumes the matching dictionary, found or not.
	svc := getMatchingService(0, matching)
	if svc == 0 {
		return nil
	}
	var conn uint32
	r := serviceOpen(svc, task, 0, &conn)
	objectRelease(svc)
	if r != 0 {
		return nil
	}
	defer serviceClose(conn)

	call := func(in *smcKeyData) (smcKeyData, bool) {
		var out smcKeyData
		size := unsafe.Sizeof(out)
		r := callStruct(conn, smcHandleYPCEvent, unsafe.Pointer(in), unsafe.Sizeof(*in),
			unsafe.Pointer(&out), &size)
		return out, r == 0 && out.result == 0
	}
	read := func(key uint32) (string, []byte, bool) {
		info, ok := call(&smcKeyData{key: key, data8: smcKeyInfo})
		if !ok || info.keyInfo.dataSize == 0 || info.keyInfo.dataSize > 32 {
			return "", nil, false
		}
		in := smcKeyData{key: key, data8: smcReadKey}
		in.keyInfo.dataSize = info.keyInfo.dataSize
		out, ok := call(&in)
		if !ok {
			return "", nil, false
		}
		return fourCCString(info.keyInfo.dataType), out.bytes[:info.keyInfo.dataSize], true
	}

	_, count, ok := read(fourCC("#KEY"))
	if !ok || len(count) != 4 {
		return nil
	}
	n := binary.BigEndian.Uint32(count)
	if n > smcMaxKeys {
		n = smcMaxKeys
	}
	temps := map[string]float64{}
	for i := uint32(0); i < n; i++ {
		at, ok := call(&smcKeyData{data8: smcKeyFromIndex, data32: i})
		if !ok {
			continue
		}
		key := fourCCString(at.key)
		if !smcTempKey(key) {
			continue
		}
		typ, data, ok := read(at.key)
		if !ok {
			continue
		}
		if c, ok := smcCelsius(typ, data); ok {
			temps[key] = c
		}
	}
	return temps
}

const (
	cfStringEncodingUTF8 = 0x08000100
	cfNumberSInt32Type   = 3

	hidEventTypeTemperature = 15
	hidUsagePageAppleVendor = 0xff00
	hidUsageTemperature     = 5
	hidMaxServices          = 512
)

func hidTemps() []hidReading {
	cf, ok := openLib(cfPath)
	if !ok {
		return nil
	}
	iokit, ok := openLib(iokitPath)
	if !ok {
		return nil
	}
	var (
		stringCreate func(alloc uintptr, s string, enc uint32) uintptr
		stringGet    func(s uintptr, buf *byte, size int, enc uint32) bool
		numberCreate func(alloc uintptr, typ int, value unsafe.Pointer) uintptr
		dictCreate   func(alloc uintptr, keys, values *uintptr, n int, keyCB, valueCB uintptr) uintptr
		arrayCount   func(a uintptr) int
		arrayAt      func(a uintptr, i int) uintptr
		release      func(o uintptr)
		typeOf       func(o uintptr) uintptr
		stringType   func() uintptr

		clientCreate func(alloc uintptr) uintptr
		setMatching  func(client, dict uintptr) int32
		copyServices func(client uintptr) uintptr
		copyProperty func(service, key uintptr) uintptr
		copyEvent    func(service uintptr, typ int64, options int32, timestamp int64) uintptr
		floatValue   func(event uintptr, field int32) float64
	)
	if !(bindSym(cf, "CFStringCreateWithCString", &stringCreate) &&
		bindSym(cf, "CFStringGetCString", &stringGet) &&
		bindSym(cf, "CFNumberCreate", &numberCreate) &&
		bindSym(cf, "CFDictionaryCreate", &dictCreate) &&
		bindSym(cf, "CFArrayGetCount", &arrayCount) &&
		bindSym(cf, "CFArrayGetValueAtIndex", &arrayAt) &&
		bindSym(cf, "CFRelease", &release) &&
		bindSym(cf, "CFGetTypeID", &typeOf) &&
		bindSym(cf, "CFStringGetTypeID", &stringType) &&
		bindSym(iokit, "IOHIDEventSystemClientCreate", &clientCreate) &&
		bindSym(iokit, "IOHIDEventSystemClientSetMatching", &setMatching) &&
		bindSym(iokit, "IOHIDEventSystemClientCopyServices", &copyServices) &&
		bindSym(iokit, "IOHIDServiceClientCopyProperty", &copyProperty) &&
		bindSym(iokit, "IOHIDServiceClientCopyEvent", &copyEvent) &&
		bindSym(iokit, "IOHIDEventGetFloatValue", &floatValue)) {
		return nil
	}
	keyCB, err := purego.Dlsym(cf, "kCFTypeDictionaryKeyCallBacks")
	if err != nil || keyCB == 0 {
		return nil
	}
	valueCB, err := purego.Dlsym(cf, "kCFTypeDictionaryValueCallBacks")
	if err != nil || valueCB == 0 {
		return nil
	}

	// Nothing made here is released on the way out: this process prints its
	// rows and exits, and a release in the wrong order is the one way left
	// for this function to crash.
	page, usage := int32(hidUsagePageAppleVendor), int32(hidUsageTemperature)
	keys := [2]uintptr{
		stringCreate(0, "PrimaryUsagePage", cfStringEncodingUTF8),
		stringCreate(0, "PrimaryUsage", cfStringEncodingUTF8),
	}
	values := [2]uintptr{
		numberCreate(0, cfNumberSInt32Type, unsafe.Pointer(&page)),
		numberCreate(0, cfNumberSInt32Type, unsafe.Pointer(&usage)),
	}
	product := stringCreate(0, "Product", cfStringEncodingUTF8)
	if keys[0] == 0 || keys[1] == 0 || values[0] == 0 || values[1] == 0 || product == 0 {
		return nil
	}
	dict := dictCreate(0, &keys[0], &values[0], 2, keyCB, valueCB)
	if dict == 0 {
		return nil
	}
	client := clientCreate(0)
	if client == 0 {
		return nil
	}
	setMatching(client, dict)
	services := copyServices(client)
	if services == 0 {
		return nil
	}
	n := arrayCount(services)
	if n > hidMaxServices {
		n = hidMaxServices
	}
	var out []hidReading
	for i := 0; i < n; i++ {
		svc := arrayAt(services, i)
		if svc == 0 {
			continue
		}
		// Every service is carried out of here, reading or not: hidRows
		// settles which sensor is which over the whole set.
		var r hidReading
		if ev := copyEvent(svc, hidEventTypeTemperature, 0, 0); ev != 0 {
			r.c, r.ok = celsiusReading(floatValue(ev, hidEventTypeTemperature<<16))
		}
		name := ""
		// A property is any CF object. Only a string may be handed to
		// CFStringGetCString; anything else given to it is not a refused
		// call but a read through the wrong layout.
		if p := copyProperty(svc, product); p != 0 && typeOf(p) == stringType() {
			var buf [128]byte
			if stringGet(p, &buf[0], len(buf), cfStringEncodingUTF8) {
				for j, b := range buf {
					if b == 0 {
						name = string(buf[:j])
						break
					}
				}
			}
		}
		r.name = name
		out = append(out, r)
	}
	return out
}
