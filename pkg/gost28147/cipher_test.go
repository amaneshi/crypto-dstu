package gost28147

import (
	"encoding/hex"
	"testing"
)

// Fixed vector from cryptonite's gost28147_mac_test, using S-box 11.
func TestMACCryptoniteVector(t *testing.T) {
	key, _ := hex.DecodeString("0100000002000000030000000400000005000000060000000700000008000000")
	data, _ := hex.DecodeString("d1ce841aa50de523b0ab76646f0d1ee8ae02aa0c4e8eafb3")
	block, err := NewCipherWithSbox(key, SboxGOST34311)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(block.(*gostCipher).MAC(data, 32)); got != "7e4a9667" {
		t.Fatalf("MAC = %s, want 7e4a9667", got)
	}
}
