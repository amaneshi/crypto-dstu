package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/csr"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/stretchr/testify/require"
)

func TestCSRCLI(t *testing.T) {
	if os.Getenv("DSTU_TEST_CSR_HELPER") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				runCSR(os.Args[i+1:])
				os.Exit(0)
			}
		}
		os.Exit(2)
	}
	for _, curve := range []string{"DSTU_PB_257", "DSTU_ONB_173", "DSTU_ONB_431"} {
		for _, digest := range []string{"default", "auto", "gost34311", "kupyna256", "kupyna512"} {
			t.Run(curve+"/"+digest, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "request.der")
				args := []string{"-test.run=^TestCSRCLI$", "--", "-curve", curve, "-cn", "CLI request", "-output", path}
				if digest != "default" {
					args = append(args, "-digest", digest)
				}
				command := exec.Command(os.Args[0], args...)
				command.Env = append(os.Environ(), "DSTU_TEST_CSR_HELPER=1")
				out, err := command.CombinedOutput()
				require.NoError(t, err, "%s", out)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				request, err := csr.Parse(data)
				require.NoError(t, err)
				require.NoError(t, request.Verify())
				expected := oid.DSTU4145WithGOST34311
				if request.PublicKey.Curve.IsONB() {
					expected = oid.DSTU4145ONBWithGOST34311
				}
				if digest == "kupyna256" {
					expected = oid.DSTU4145WithKupyna256
					if request.PublicKey.Curve.IsONB() {
						expected = oid.DSTU4145ONBWithKupyna256
					}
				}
				if digest == "kupyna512" {
					expected = oid.DSTU4145WithKupyna512
					if request.PublicKey.Curve.IsONB() {
						expected = oid.DSTU4145ONBWithKupyna512
					}
				}
				require.Equal(t, expected, request.SignatureAlgOID)
			})
		}
	}
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[existing], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "request.der")
			original := []byte("preserve existing output")
			if existing {
				require.NoError(t, os.WriteFile(path, original, 0600))
			}
			command := exec.Command(os.Args[0], "-test.run=^TestCSRCLI$", "--", "-cn", "Request", "-curve", "invalid", "-digest", "sha256", "-output", path)
			command.Env = append(os.Environ(), "DSTU_TEST_CSR_HELPER=1")
			out, err := command.CombinedOutput()
			require.Error(t, err)
			require.Contains(t, string(out), "unknown digest")
			data, err := os.ReadFile(path)
			if existing {
				require.NoError(t, err)
				require.Equal(t, original, data)
			} else {
				require.True(t, os.IsNotExist(err))
			}
		})
	}
}
