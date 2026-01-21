package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
)

func main() {
	// The original string (URL-safe Base64)
	input := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW_0IGDyIKy_lA10CIjNV4dy3G1jVLIhabzRLJJDSD9nesZLv6Pqe0MVRGjncQkCjh4lOwOsOwMbdRaux8R912w=="

	// 1. Decode using URLEncoding
	// We must use URLEncoding because the input contains '-' characters
	rawBytes, err := base64.URLEncoding.DecodeString(input)
	if err != nil {
		log.Fatalf("Failed to decode: %v", err)
	}

	// 2. Parse the PKIX Public Key
	_, err = x509.ParsePKIXPublicKey(rawBytes)
	if err != nil {
		log.Fatalf("Parse failed: %v", err)
	}
	keyHash := keyHashECDSA(rawBytes)

	// 3. Re-encode using StdEncoding
	// StdEncoding uses '+' and '/' characters
	standardOutput := base64.StdEncoding.EncodeToString(append([]byte{byte(2)}, rawBytes...))

	fmt.Printf("recoverylog.chromebook.com+%08x+%s\n", keyHash, standardOutput)
}

func keyHashECDSA(i []byte) uint32 {
	h := sha256.Sum256(i)
	return binary.BigEndian.Uint32(h[:])
}
