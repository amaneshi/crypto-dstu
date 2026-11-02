package dstu4145

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestONBParametersRemainUnsupported(t *testing.T) {
	data, err := os.ReadFile("testdata/onb-cryptonite.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Source  string
		Vectors []struct{ Name, OID, ParametersHex string }
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 5 || fixture.Source == "" {
		t.Fatal("missing independent ONB fixture provenance")
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			parameters, err := hex.DecodeString(v.ParametersHex)
			if err != nil {
				t.Fatal(err)
			}
			if ParamsFromDER(parameters) != nil {
				t.Fatal("ONB explicit coordinates must not be interpreted as a PB curve of the same size")
			}
			var oid asn1.ObjectIdentifier
			for _, part := range strings.Split(v.OID, ".") {
				n, err := strconv.Atoi(part)
				if err != nil {
					t.Fatal(err)
				}
				oid = append(oid, n)
			}
			if ParamsByOID(oid) != nil {
				t.Fatal("unsupported ONB named curve was accepted")
			}
			named, err := asn1.Marshal(struct{ Curve asn1.ObjectIdentifier }{oid})
			if err != nil {
				t.Fatal(err)
			}
			if ParamsFromDER(named) != nil {
				t.Fatal("unsupported ONB named parameters were accepted")
			}
		})
	}
}
