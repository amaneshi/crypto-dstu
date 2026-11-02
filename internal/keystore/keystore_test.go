package keystore

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/ec"

	"github.com/stretchr/testify/require"
)

// ---- PEM tests ----

func TestIsPEM(t *testing.T) {
	pem := []byte("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n")
	if !IsPEM(pem) {
		t.Error("expected IsPEM=true for PEM data")
	}
	if IsPEM([]byte{0x30, 0x82, 0x01}) {
		t.Error("expected IsPEM=false for DER data")
	}
}

func TestDecodePEMRoundtrip(t *testing.T) {
	original := []byte{0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	pemData := EncodePEM(original, "TEST KEY")
	if !IsPEM(pemData) {
		t.Fatal("EncodePEM did not produce PEM")
	}
	decoded, typ, err := DecodePEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if typ != "TEST KEY" {
		t.Errorf("type = %q, want %q", typ, "TEST KEY")
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("roundtrip mismatch: got %x, want %x", decoded, original)
	}
}

func TestMaybePEM(t *testing.T) {
	der := []byte{0x30, 0x00}
	pemData := EncodePEM(der, "RAW")
	// MaybePEM on PEM input returns the DER
	got := MaybePEM(pemData)
	if !bytes.Equal(got, der) {
		t.Errorf("MaybePEM(PEM) = %x, want %x", got, der)
	}
	// MaybePEM on DER input returns unchanged
	got2 := MaybePEM(der)
	if !bytes.Equal(got2, der) {
		t.Errorf("MaybePEM(DER) changed the input")
	}
}

// ---- Raw PKCS#8 tests ----

func TestRawKeyRoundtrip(t *testing.T) {
	for _, curve := range []*ec.Curve{ec.DSTU_PB_257(), ec.DSTU_PB_163()} {
		t.Run(curve.String(), func(t *testing.T) {
			priv, err := dstu4145.GenerateKey(curve)
			if err != nil {
				t.Fatal(err)
			}

			der, err := MarshalRawKey(priv)
			if err != nil {
				t.Fatalf("MarshalRawKey: %v", err)
			}

			priv2, err := ParseRawKey(der)
			if err != nil {
				t.Fatalf("ParseRawKey: %v", err)
			}

			if priv.D.Cmp(priv2.D) != 0 {
				t.Errorf("D mismatch after roundtrip")
			}
			if priv.Curve.M != priv2.Curve.M || string(priv.Curve.N) != string(priv2.Curve.N) {
				t.Errorf("Curve mismatch after roundtrip")
			}
		})
	}
}

func TestParseRawKeyPEMRoundtrip(t *testing.T) {
	priv, _ := dstu4145.GenerateKey(ec.DSTU_PB_257())
	der, _ := MarshalRawKey(priv)

	pemData := EncodePEM(der, "PRIVATE KEY")
	decoded := MaybePEM(pemData)

	priv2, err := ParseRawKey(decoded)
	if err != nil {
		t.Fatalf("ParseRawKey from PEM: %v", err)
	}
	if priv.D.Cmp(priv2.D) != 0 {
		t.Error("D mismatch after PEM roundtrip")
	}
}

func TestParseRawKeyBadVersion(t *testing.T) {
	priv, _ := dstu4145.GenerateKey(ec.DSTU_PB_257())
	der, _ := MarshalRawKey(priv)

	// Corrupt version byte (first INTEGER in the SEQUENCE)
	// The DER starts: 30 xx 02 01 00 ...  → change 00 to 01
	for i := 0; i+3 < len(der); i++ {
		if der[i] == 0x02 && der[i+1] == 0x01 && der[i+2] == 0x00 {
			der[i+2] = 0x01
			break
		}
	}
	_, err := ParseRawKey(der)
	if err == nil {
		t.Error("expected error for bad version, got nil")
	}
}

func TestParseRawKeyUnknownOID(t *testing.T) {
	priv, _ := dstu4145.GenerateKey(ec.DSTU_PB_257())
	der, _ := MarshalRawKey(priv)

	// Unmarshal and re-marshal with a garbage OID
	var ki privateKeyInfo
	_, err := asn1.Unmarshal(der, &ki)
	require.NoError(t, err)
	ki.Algorithm.Algorithm = asn1.ObjectIdentifier{9, 9, 9, 9}
	badDER, _ := asn1.Marshal(ki)

	_, err = ParseRawKey(badDER)
	require.Error(t, err)
}

// ---- PBKDF2-GOST34311 tests ----

func TestPBKDF2GOSTDeterminism(t *testing.T) {
	pass := []byte("test-password")
	salt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	k1, err := pbkdf2GOST(pass, salt, 1000, 32, true)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := pbkdf2GOST(pass, salt, 1000, 32, true)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k1, k2) {
		t.Error("PBKDF2-GOST is not deterministic")
	}
	if len(k1) != 32 {
		t.Errorf("key length = %d, want 32", len(k1))
	}
}

func TestPBKDF2GOSTDifferentPasswords(t *testing.T) {
	salt := []byte{0x01, 0x02, 0x03, 0x04}
	k1, _ := pbkdf2GOST([]byte("pass1"), salt, 10, 32, true)
	k2, _ := pbkdf2GOST([]byte("pass2"), salt, 10, 32, true)
	if bytes.Equal(k1, k2) {
		t.Error("PBKDF2-GOST should differ for different passwords")
	}
}

func TestPBKDF2GOSTDifferentSalts(t *testing.T) {
	pass := []byte("pass")
	k1, _ := pbkdf2GOST(pass, []byte("salt1"), 10, 32, true)
	k2, _ := pbkdf2GOST(pass, []byte("salt2"), 10, 32, true)
	if bytes.Equal(k1, k2) {
		t.Error("PBKDF2-GOST should differ for different salts")
	}
}

func TestPBKDF2GOSTKeyLength(t *testing.T) {
	for _, keyLen := range []int{16, 24, 32, 64} {
		k, err := pbkdf2GOST([]byte("pass"), []byte("salt"), 1, keyLen, true)
		if err != nil {
			t.Fatalf("keyLen=%d: %v", keyLen, err)
		}
		if len(k) != keyLen {
			t.Errorf("keyLen=%d: got %d bytes", keyLen, len(k))
		}
	}
}

func TestHMACGost34311NonZero(t *testing.T) {
	h := hmacGost34311([]byte("key"), []byte("data"))
	if len(h) != 32 {
		t.Errorf("HMAC-GOST34311 length = %d, want 32", len(h))
	}
	allZero := true
	for _, b := range h {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("HMAC-GOST34311 output is all zeros")
	}
}

// ---- Key-6.dat round-trip: encrypt then decrypt ----

func TestKey6EncryptDecryptRoundtrip(t *testing.T) {
	curve := ec.DSTU_PB_257()
	priv, err := dstu4145.GenerateKey(curve)
	if err != nil {
		t.Fatal(err)
	}
	password := "test-password-123"

	// Marshal to raw PKCS#8 first
	rawDER, err := MarshalRawKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt to Key-6.dat format
	salt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	iv := []byte{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18}
	encrypted, err := MarshalKey6(rawDER, password, salt, 1000, iv)
	if err != nil {
		t.Fatalf("MarshalKey6: %v", err)
	}

	// Decrypt
	priv2, err := ParseKey6(encrypted, password)
	if err != nil {
		t.Fatalf("ParseKey6: %v", err)
	}

	if priv.D.Cmp(priv2.D) != 0 {
		t.Error("D mismatch after Key-6 roundtrip")
	}
}

func TestKey6WrongPassword(t *testing.T) {
	priv, _ := dstu4145.GenerateKey(ec.DSTU_PB_257())
	rawDER, _ := MarshalRawKey(priv)

	salt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	iv := []byte{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18}
	encrypted, _ := MarshalKey6(rawDER, "correct-password", salt, 1000, iv)

	_, err := ParseKey6(encrypted, "wrong-password")
	if err == nil {
		t.Error("expected error with wrong password, got nil")
	}
}

// ---- JKS tests ----

func TestJKSParseEmpty(t *testing.T) {
	_, err := ParseJKS([]byte("not a jks"))
	if err == nil {
		t.Error("expected error for invalid JKS")
	}
}

func TestFindByRole(t *testing.T) {
	entries := []JKSEntry{
		{Alias: "personal_key_0"},
		{Alias: "stamp_key_1"},
		{Alias: "director_key_2"},
	}
	e := FindByRole(entries, RoleStamp)
	if e == nil || e.Alias != "stamp_key_1" {
		t.Errorf("FindByRole(stamp) = %v", e)
	}
	e = FindByRole(entries, RolePersonal)
	if e == nil || e.Alias != "personal_key_0" {
		t.Errorf("FindByRole(personal) = %v", e)
	}
	e = FindByRole(entries, RoleFOP)
	if e != nil {
		t.Errorf("FindByRole(fop) should be nil, got %v", e)
	}
}

// ---- Auto-detection (Parse) tests ----

func TestParseRawKey_viaGuess(t *testing.T) {
	priv, _ := dstu4145.GenerateKey(ec.DSTU_PB_257())
	der, _ := MarshalRawKey(priv)

	result, err := Parse(der, "")
	if err != nil {
		t.Fatalf("Parse(raw DER): %v", err)
	}
	if result.Format != FormatRaw {
		t.Errorf("Format = %q, want %q", result.Format, FormatRaw)
	}
	if len(result.Keys) != 1 {
		t.Fatalf("Keys count = %d, want 1", len(result.Keys))
	}
	if result.Keys[0].D.Cmp(priv.D) != 0 {
		t.Error("D mismatch from Parse(raw DER)")
	}
}

func TestParseKey6_viaGuess(t *testing.T) {
	priv, _ := dstu4145.GenerateKey(ec.DSTU_PB_257())
	rawDER, _ := MarshalRawKey(priv)
	password := "hunter2"
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	iv := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	enc, _ := MarshalKey6(rawDER, password, salt, 200, iv)

	result, err := Parse(enc, password)
	if err != nil {
		t.Fatalf("Parse(key6): %v", err)
	}
	if result.Format != FormatKey6 {
		t.Errorf("Format = %q, want %q", result.Format, FormatKey6)
	}
	if result.Keys[0].D.Cmp(priv.D) != 0 {
		t.Error("D mismatch from Parse(key6)")
	}
}

func TestParsePEMWrapped_viaGuess(t *testing.T) {
	priv, _ := dstu4145.GenerateKey(ec.DSTU_PB_257())
	der, _ := MarshalRawKey(priv)
	pemData := EncodePEM(der, "PRIVATE KEY")

	result, err := Parse(pemData, "")
	if err != nil {
		t.Fatalf("Parse(PEM): %v", err)
	}
	if result.Format != FormatPEM {
		t.Errorf("Format = %q, want %q", result.Format, FormatPEM)
	}
}

func TestParseUnknownFormat(t *testing.T) {
	_, err := Parse([]byte{0xFF, 0xFE, 0xFD}, "pass")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

// ---- Scalar range check ----

func TestParseRawKeyScalarOutOfRange(t *testing.T) {
	priv, _ := dstu4145.GenerateKey(ec.DSTU_PB_257())
	curve := ec.DSTU_PB_257()
	der, _ := MarshalRawKey(priv)

	// Replace the private key bytes with zeros to produce d=0 (invalid scalar)
	var ki privateKeyInfo
	_, err := asn1.Unmarshal(der, &ki)
	require.NoError(t, err)
	ki.PrivateKey = make([]byte, (curve.M+7)/8)
	badDER, _ := asn1.Marshal(ki)

	_, err = ParseRawKey(badDER)
	require.Error(t, err)
}
