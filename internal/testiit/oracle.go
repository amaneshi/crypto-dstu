package testiit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type Request struct {
	Cipher           string   `json:"cipher,omitempty"`
	Recipients       [][]byte `json:"recipients,omitempty"`
	StaticOriginator bool     `json:"static_originator,omitempty"`
	KeyFamily        string   `json:"key_family,omitempty"`
	KeyBits          int      `json:"key_bits,omitempty"`
	Digest           string   `json:"digest,omitempty"`
	RequireTimestamp bool     `json:"require_timestamp,omitempty"`
	Operation        string   `json:"operation"`
	Data             []byte   `json:"data"`
	Signature        []byte   `json:"signature,omitempty"`
	Detached         bool     `json:"detached,omitempty"`
	Certificates     [][]byte `json:"certificates,omitempty"`
	PrivateKey       []byte   `json:"private_key,omitempty"`
	Password         string   `json:"password,omitempty"`
}
type Response struct {
	OK      bool   `json:"ok"`
	Data    []byte `json:"data"`
	Error   string `json:"error"`
	Code    uint32 `json:"code"`
	Policy  string `json:"policy"`
	SDKHash string `json:"sdk_sha256"`
}

func Invoke(t testing.TB, request Request) Response {
	t.Helper()
	oracle, sdk := os.Getenv("IIT_ORACLE"), os.Getenv("IIT_SDK_DIR")
	if oracle == "" || sdk == "" {
		t.Skip("set IIT_ORACLE and IIT_SDK_DIR for native IIT interoperability")
	}
	require.True(t, filepath.IsAbs(oracle))
	require.True(t, filepath.IsAbs(sdk))
	input, err := json.Marshal(request)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, oracle, "-sdk", sdk)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	require.NoError(t, ctx.Err(), "IIT timeout")
	var result Response
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &result), "IIT runner: %v; stderr: %s", runErr, stderr.String())
	require.Equal(t, "offline-no-revocation", result.Policy)
	require.Len(t, result.SDKHash, 64)
	if pin := os.Getenv("IIT_SDK_SHA256"); pin != "" {
		require.Equal(t, strings.ToLower(pin), result.SDKHash)
	}
	if result.OK {
		require.NoError(t, runErr)
	} else {
		require.Error(t, runErr)
		require.NotEmpty(t, result.Error)
		require.Empty(t, result.Data)
	}
	return result
}
