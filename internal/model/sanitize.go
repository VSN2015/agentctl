package model

import "strings"

// Sanitize replaces control and bidi-override characters with '?' so
// untrusted text cannot inject terminal escapes or spoof layout.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x200e || r == 0x200f || r == 0x061c || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return '?'
		}
		return r
	}, s)
}

// MaskKeyID keeps the first and last four characters; short IDs are fully hidden.
func MaskKeyID(id string) string {
	if id == "" {
		return ""
	}
	if len(id) < 12 {
		return "****"
	}
	return id[:4] + "****" + id[len(id)-4:]
}
