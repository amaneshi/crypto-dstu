package keystore

import (
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
)

func FuzzPKCS12AuthenticatedSafe(f *testing.F) {
	marshal := func(value any) []byte {
		data, err := asn1.Marshal(value)
		if err != nil {
			f.Fatal(err)
		}
		return data
	}
	// Public scalar d=1 is intentional; no operational credentials are used.
	key := &dstu4145.PrivateKey{Curve: dstu4145.ParamsByName("DSTU_PB_257").Curve, D: big.NewInt(1)}
	raw, err := MarshalRawKey(key)
	if err != nil {
		f.Fatal(err)
	}
	bags := marshal([]safeBag{{BagID: oidKeyBag, BagValue: p12Explicit(raw)}})
	f.Add(marshal([]contentInfo{{ContentType: oidDataContentType, Content: p12Explicit(marshal(bags))}}))
	f.Add([]byte{0x30, 0})
	f.Add([]byte{0x30, 0xff})
	f.Fuzz(func(t *testing.T, safe []byte) {
		if len(safe) > 64<<10 {
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
