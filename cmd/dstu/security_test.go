package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnsupportedSigningOptionsDoNotWriteOutput(t *testing.T) {
	if os.Getenv("DSTU_TEST_SIGN_HELPER") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				runSign(os.Args[i+1:])
				return
			}
		}
		os.Exit(2)
	}
	for _, args := range [][]string{{"-tsp-level", "content"}, {"-tsp-level", "all"}, {"-include-chain", "full"}} {
		t.Run(args[0], func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "signature.p7s")
			cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestUnsupportedSigningOptionsDoNotWriteOutput$", "--", "-output", output}, args...)...)
			cmd.Env = append(os.Environ(), "DSTU_TEST_SIGN_HELPER=1")
			stderr, err := cmd.CombinedOutput()
			require.Error(t, err)
			require.Contains(t, string(stderr), "not implemented")
			_, err = os.Stat(output)
			require.True(t, os.IsNotExist(err))
		})
	}
}
