package secure

import (
	"crypto/tls"
	"strings"
)

// Cipher names referenced only to REJECT or translate them must not trigger
// weak-cipher findings.

func rejectRC4(id uint16) bool {
	switch id {
	case tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return true
	}
	return false
}

func rejectRC4ByName(name string) bool {
	return strings.Contains(name, "RC4")
}

func rejectRC4NameSwitch(name string) bool {
	switch name {
	case "TLS_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA":
		return true
	}
	return false
}

var openSSLToGoCipher = map[string]uint16{
	"DES-CBC3-SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"ECDHE-RSA-DES-CBC3-SHA": tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"AES128-SHA":             tls.TLS_RSA_WITH_AES_128_CBC_SHA,
}
