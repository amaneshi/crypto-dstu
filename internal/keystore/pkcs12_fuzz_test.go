package keystore

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func FuzzPKCS12AuthenticatedSafe(f *testing.F) {
	marshal := func(value any) []byte {
		data, err := asn1.Marshal(value)
		if err != nil {
			f.Fatal(err)
		}
		return data
	}
	addValidSafe := func(safe []byte) {
		pairs, err := ParsePKCS12(p12DER(f, p12Sign(f, safe, fuzzPassword)), fuzzPassword)
		require.NoError(f, err, "valid privacy/association seed must reach key import")
		require.NotEmpty(f, pairs)
		f.Add(safe)
	}
	// Public scalar d=1 is intentional; no operational credentials are used.
	key := &dstu4145.PrivateKey{Curve: dstu4145.ParamsByName("DSTU_PB_257").Curve, D: big.NewInt(1)}
	raw, err := MarshalRawKey(key)
	if err != nil {
		f.Fatal(err)
	}
	bags := marshal([]safeBag{{BagID: oidKeyBag, BagValue: p12Explicit(raw)}})
	addValidSafe(marshal([]contentInfo{{ContentType: oidDataContentType, Content: p12Explicit(marshal(bags))}}))
	certificate := testiit.NamedCertificate(f, key)
	for _, modern := range []bool{false, true} {
		protected, err := MarshalKey6(raw, fuzzPassword, bytes.Repeat([]byte{0x53}, 32), 2, bytes.Repeat([]byte{0x49}, 8))
		require.NoError(f, err)
		if modern {
			protected, err = MarshalKey6Kalyna(
				raw, fuzzPassword, bytes.Repeat([]byte{0x53}, 32), 2, bytes.Repeat([]byte{0x49}, 32),
			)
			require.NoError(f, err)
		}
		contents := marshal([]safeBag{
			{BagID: oidPKCS8ShroudedKeyBag, BagValue: p12Explicit(protected)},
			p12CertBag(f, certificate.Raw),
		})
		addValidSafe(marshal([]contentInfo{{ContentType: oidDataContentType, Content: p12Explicit(marshal(contents))}}))
		// Protect an entire SafeContents as well as an individual key bag.
		protected, err = MarshalKey6Kalyna(
			bags, fuzzPassword, bytes.Repeat([]byte{0x53}, 32), 2, bytes.Repeat([]byte{0x49}, 32),
		)
		require.NoError(f, err)
		var info encryptedPrivateKeyInfo
		_, err = asn1.Unmarshal(protected, &info)
		require.NoError(f, err)
		ed := encryptedData{EncryptedContentInfo: encryptedContentInfo{
			ContentType: oidDataContentType, ContentEncAlgorithm: info.Algorithm,
			EncryptedContent: asn1.RawValue{Class: 2, Tag: 0, Bytes: info.EncryptedData},
		}}
		addValidSafe(marshal([]contentInfo{{ContentType: oidEncryptedDataContentType, Content: p12Explicit(marshal(ed))}}))
	}
	f.Add(marshal([]contentInfo{{ContentType: oidDataContentType, Content: p12Explicit(marshal(marshal([]safeBag{
		{BagID: oidKeyBag, BagValue: p12Explicit(raw)}, {BagID: oidKeyBag, BagValue: p12Explicit(raw)},
	})))}}))
	f.Add([]byte{0x30, 0})
	f.Add([]byte{0x30, 0xff})
	f.Fuzz(func(t *testing.T, safe []byte) {
		if len(safe) > 64<<10 || !fuzzSafeBudget(safe) {
			return
		}
		// Authenticate arbitrary inner bytes with a public password, reaching
		// the parsers beyond the MAC gate without weakening production policy.
		data := p12DER(t, p12Sign(t, safe, "public-fuzz-password"))
		pairs, err := ParsePKCS12(data, "public-fuzz-password")
		if err != nil && pairs != nil {
			t.Fatal("failed PFX parse released keys")
		}
	})
}

func fuzzSafeBudget(safe []byte) bool {
	var contents []contentInfo
	if _, err := asn1.Unmarshal(safe, &contents); err != nil {
		return true
	}
	for _, content := range contents {
		var bags []byte
		switch {
		case content.ContentType.Equal(oidDataContentType):
			if _, err := asn1.Unmarshal(content.Content.Bytes, &bags); err != nil {
				continue
			}
		case content.ContentType.Equal(oidEncryptedDataContentType):
			var ed encryptedData
			if _, err := asn1.Unmarshal(content.Content.Bytes, &ed); err != nil {
				continue
			}
			if !fuzzPBES2Budget(ed.EncryptedContentInfo.ContentEncAlgorithm) {
				return false
			}
			p, kdf, err := parsePBES2Parameters(ed.EncryptedContentInfo.ContentEncAlgorithm)
			if err != nil {
				continue
			}
			bags, err = decryptPBES2Data(p, kdf, ed.EncryptedContentInfo.EncryptedContent.Bytes, []byte(fuzzPassword))
			if err != nil {
				continue
			}
		}
		var entries []safeBag
		if _, err := asn1.Unmarshal(bags, &entries); err != nil {
			continue
		}
		for _, bag := range entries {
			if bag.BagID.Equal(oidPKCS8ShroudedKeyBag) && !fuzzKey6Budget(bag.BagValue.Bytes) {
				return false
			}
		}
	}
	return true
}

func FuzzParsePKCS12(f *testing.F) {
	raw := fuzzRawKey(f, "DSTU_PB_257")
	safe := p12DER(f, []contentInfo{{ContentType: oidDataContentType, Content: p12Explicit(p12DER(f,
		p12DER(f, []safeBag{{BagID: oidKeyBag, BagValue: p12Explicit(raw)}})))}})
	f.Add(p12DER(f, p12Sign(f, safe, fuzzPassword)))
	pairs, err := ParsePKCS12(p12DER(f, p12Sign(f, safe, fuzzPassword)), fuzzPassword)
	require.NoError(f, err)
	require.NotEmpty(f, pairs)
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		var outer pfxASN
		if _, err := asn1.Unmarshal(data, &outer); err == nil {
			var mac pkcs12MacData
			_, macErr := asn1.Unmarshal(outer.MacData.FullBytes, &mac)
			if macErr == nil && mac.Iterations > 256 && mac.Iterations <= 1_000_000 {
				return
			}
			if safe, err := pkcs12AuthenticatedSafe(outer.AuthSafe); err == nil && !fuzzSafeBudget(safe) {
				return
			}
		}
		original := bytes.Clone(data)
		pairs, err := ParsePKCS12(data, fuzzPassword)
		require.Equal(t, original, data)
		if err != nil {
			require.Nil(t, pairs)
		} else {
			require.NotEmpty(t, pairs)
			var mac pkcs12MacData
			_, err = asn1.Unmarshal(outer.MacData.FullBytes, &mac)
			require.NoError(t, err)
			mac.MAC.Digest[0] ^= 1
			outer.MacData = p12Raw(t, mac)
			pairs, err = ParsePKCS12(p12DER(t, outer), fuzzPassword)
			require.Error(t, err)
			require.Nil(t, pairs)
		}
	})
}
