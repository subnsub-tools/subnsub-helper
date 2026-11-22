package main

// The Mac's virtual key codes as the X11 keysyms Screen Sharing takes
// (screenhp.go). A key is sent by what it is on a US keyboard: the Mac at the
// other end turns it back into its key with its own layout, and Shift,
// Option and the rest held there make of it what they make.
//
// Screen Sharing reads the modifiers its own way (held one at a time against
// macOS 15 on 2026-11-22, reading the Mac's modifier flags): Super is
// Command, Alt is Command too, Meta is Option, Control is Control.
const (
	hpKeysymCommandL uint32 = 0xffeb // Super_L
	hpKeysymCommandR uint32 = 0xffec // Super_R
	hpKeysymOptionL  uint32 = 0xffe7 // Meta_L
	hpKeysymOptionR  uint32 = 0xffe8 // Meta_R
)

var macKeysyms = map[uint16]uint32{
	0x00: 'a', 0x01: 's', 0x02: 'd', 0x03: 'f', 0x04: 'h', 0x05: 'g', 0x06: 'z', 0x07: 'x',
	0x08: 'c', 0x09: 'v', 0x0A: 0xa7, 0x0B: 'b', 0x0C: 'q', 0x0D: 'w', 0x0E: 'e', 0x0F: 'r',
	0x10: 'y', 0x11: 't', 0x12: '1', 0x13: '2', 0x14: '3', 0x15: '4', 0x16: '6', 0x17: '5',
	0x18: '=', 0x19: '9', 0x1A: '7', 0x1B: '-', 0x1C: '8', 0x1D: '0', 0x1E: ']', 0x1F: 'o',
	0x20: 'u', 0x21: '[', 0x22: 'i', 0x23: 'p', 0x25: 'l', 0x26: 'j', 0x27: '\'', 0x28: 'k',
	0x29: ';', 0x2A: '\\', 0x2B: ',', 0x2C: '/', 0x2D: 'n', 0x2E: 'm', 0x2F: '.', 0x31: ' ',
	0x32: '`',
	0x24: 0xff0d, // Return
	0x30: 0xff09, // Tab
	0x33: 0xff08, // BackSpace (the Mac's Delete)
	0x34: 0xff8d, // KP_Enter (a PowerBook's Enter)
	0x35: 0xff1b, // Escape
	0x38: 0xffe1, // Shift_L
	0x39: 0xffe5, // Caps_Lock
	0x3A: hpKeysymOptionL,
	0x3B: 0xffe3, // Control_L
	0x3C: 0xffe2, // Shift_R
	0x3D: hpKeysymOptionR,
	0x3E: 0xffe4,                                                                                                   // Control_R
	0x40: 0xffce,                                                                                                   // F17
	0x41: 0xffae,                                                                                                   // KP_Decimal
	0x43: 0xffaa,                                                                                                   // KP_Multiply
	0x45: 0xffab,                                                                                                   // KP_Add
	0x47: 0xff7f,                                                                                                   // Num_Lock (the keypad's Clear)
	0x48: 0x1008ff13,                                                                                               // XF86AudioRaiseVolume
	0x49: 0x1008ff11,                                                                                               // XF86AudioLowerVolume
	0x4A: 0x1008ff12,                                                                                               // XF86AudioMute
	0x4B: 0xffaf,                                                                                                   // KP_Divide
	0x4C: 0xff8d,                                                                                                   // KP_Enter
	0x4E: 0xffad,                                                                                                   // KP_Subtract
	0x4F: 0xffcf,                                                                                                   // F18
	0x50: 0xffd0,                                                                                                   // F19
	0x51: 0xffbd,                                                                                                   // KP_Equal
	0x52: 0xffb0, 0x53: 0xffb1, 0x54: 0xffb2, 0x55: 0xffb3, 0x56: 0xffb4, 0x57: 0xffb5, 0x58: 0xffb6, 0x59: 0xffb7, // KP_0 … KP_7
	0x5A: 0xffd1,               // F20
	0x5B: 0xffb8, 0x5C: 0xffb9, // KP_8, KP_9
	0x5D: 0xa5,                                                                         // the JIS keyboard's ¥
	0x5E: '_',                                                                          // the JIS keyboard's _
	0x5F: 0xffac,                                                                       // KP_Separator (the JIS keypad's comma)
	0x60: 0xffc2, 0x61: 0xffc3, 0x62: 0xffc4, 0x63: 0xffc0, 0x64: 0xffc5, 0x65: 0xffc6, // F5 F6 F7 F3 F8 F9
	0x66: 0xff30, // Eisu_toggle (the JIS keyboard's Eisu)
	0x67: 0xffc8, // F11
	0x68: 0xff2e, // Kana_Shift (the JIS keyboard's Kana)
	0x69: 0xffca, // F13
	0x6A: 0xffcd, // F16
	0x6B: 0xffcb, // F14
	0x6D: 0xffc7, // F10
	0x6F: 0xffc9, // F12
	0x71: 0xffcc, // F15
	0x72: 0xff63, // Insert (Help)
	0x73: 0xff50, // Home
	0x74: 0xff55, // Page_Up
	0x75: 0xffff, // Delete (forward)
	0x76: 0xffc1, // F4
	0x77: 0xff57, // End
	0x78: 0xffbf, // F2
	0x79: 0xff56, // Page_Down
	0x7A: 0xffbe, // F1
	0x7B: 0xff51, // Left
	0x7C: 0xff53, // Right
	0x7D: 0xff54, // Down
	0x7E: 0xff52, // Up
}

// macKeysym is the keysym for one of the Mac's virtual key codes; 0 for a
// key that has none (Fn).
func macKeysym(code uint16) uint32 {
	switch code {
	case 0x37:
		return hpKeysymCommandL
	case 0x36:
		return hpKeysymCommandR
	}
	return macKeysyms[code]
}

// runeKeysym is the keysym that types one character: Latin-1 as itself, the
// rest of Unicode as 0x01000000 plus its code point, as X11 has them. 0 for
// what types nothing.
func runeKeysym(r rune) uint32 {
	switch {
	case r == '\n' || r == '\r':
		return 0xff0d
	case r == '\t':
		return 0xff09
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
		return 0
	case r <= 0xff:
		return uint32(r)
	case r <= 0x10ffff:
		return 0x01000000 | uint32(r)
	}
	return 0
}
