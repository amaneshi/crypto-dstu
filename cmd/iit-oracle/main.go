// Command iit-oracle is an optional, offline interoperability test adapter.
// It is not linked into the crypto-dstu library.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Byte slices use JSON's standard base64 representation. Requests contain test
// material only; the runner never reads a user's key store or configuration.
type request struct {
	Cipher           string   `json:"cipher,omitempty"`
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
	Recipients       [][]byte `json:"recipients,omitempty"`
	StaticOriginator bool     `json:"static_originator,omitempty"`
}
type response struct {
	OK      bool   `json:"ok"`
	Data    []byte `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
	Code    uint32 `json:"code,omitempty"`
	Policy  string `json:"policy"`
	SDKHash string `json:"sdk_sha256,omitempty"`
}

func main() {
	sdk := flag.String("sdk", "", "absolute directory containing a matching-architecture IIT SDK")
	flag.Parse()
	result := run(*sdk, os.Stdin)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !result.OK {
		os.Exit(1)
	}
}

func run(sdk string, input io.Reader) response {
	result := response{Policy: "offline-no-revocation"}
	var req request
	decoder := json.NewDecoder(io.LimitReader(input, 8<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		result.Error = "decode request: " + err.Error()
		return result
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		result.Error = "request must contain one JSON object"
		return result
	}
	switch req.Operation {
	case "hash", "verify", "sign", "generate", "encrypt", "decrypt", "key-info", "cert-parse":
	default:
		result.Error = "supported operations: hash, verify, sign, generate, encrypt, decrypt, key-info, cert-parse"
		return result
	}
	if req.Operation == "cert-parse" && len(req.Data) == 0 {
		result.Error = "cert-parse requires certificate data"
		return result
	}
	if req.RequireTimestamp && req.Operation != "verify" {
		result.Error = "require_timestamp is only valid for verify"
		return result
	}
	if req.Cipher != "" {
		if req.Operation != "encrypt" || !req.StaticOriginator {
			result.Error = "cipher selection requires static-originator encrypt"
			return result
		}
		if req.Cipher != "kalyna256-cfb" && req.Cipher != "kalyna256-ofb" {
			result.Error = "unsupported content cipher"
			return result
		}
	}
	if req.Digest != "" {
		if req.Operation != "hash" && req.Operation != "sign" {
			result.Error = "digest is only valid for hash or sign"
			return result
		}
		if _, err := digestProfile(req.Digest); err != nil {
			result.Error = err.Error()
			return result
		}
		if req.Operation == "sign" && req.Digest == "kupyna512" && !req.Detached {
			if len(req.Data) == 0 {
				result.Error = "native Kupyna512 attached signing requires nonempty content"
				return result
			}
			if len(req.Certificates) != 1 {
				result.Error = "native Kupyna512 attached signing requires exactly one signer certificate"
				return result
			}
		}
	}
	if req.KeyBits != 0 || req.KeyFamily != "" {
		if req.Operation != "generate" {
			result.Error = "key_bits/key_family are only valid for generate"
			return result
		}
		if _, _, err := generationParameters(req.KeyFamily, req.KeyBits); err != nil {
			result.Error = err.Error()
			return result
		}
	}
	if !filepath.IsAbs(sdk) {
		result.Error = "-sdk must be an absolute path"
		return result
	}
	for _, r := range sdk {
		if r > 127 {
			result.Error = "IIT ANSI interface requires an ASCII SDK path"
			return result
		}
	}
	b, err := os.ReadFile(filepath.Join(sdk, "EUSignCP.dll"))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	hash := sha256.Sum256(b)
	result.SDKHash = hex.EncodeToString(hash[:])
	config, err := os.MkdirTemp("", "crypto-dstu-iit-")
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer os.RemoveAll(config)
	if err = os.WriteFile(filepath.Join(config, "osplm.ini"), nil, 0600); err != nil {
		result.Error = err.Error()
		return result
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result.Data, err = execute(sdk, config, req)
	if err != nil {
		result.Data = nil
		result.Error = err.Error()
		var native *nativeError
		if errors.As(err, &native) {
			result.Code = native.Code
		}
		return result
	}
	result.OK = true
	return result
}

type nativeError struct {
	Function    string
	Code        uint32
	Description string
}

func (e *nativeError) Error() string {
	return fmt.Sprintf("%s: IIT error %d: %s", e.Function, e.Code, e.Description)
}

// A CMS signingTime is not a timestamp. This guard is applied only after the
// native verifier succeeds, and never replaces token signature/imprint checks.
func checkTimestampRequirement(required, hasSignatureTimestamp bool) error {
	if required && !hasSignatureTimestamp {
		return errors.New("IIT did not report a verified timestamp")
	}
	return nil
}

type nativeDigestProfile struct {
	Hash, Sign uint32
	Size       int
}

func digestProfile(name string) (nativeDigestProfile, error) {
	switch name {
	case "gost34311":
		return nativeDigestProfile{1, 1, 32}, nil
	case "kupyna256":
		return nativeDigestProfile{7, 4, 32}, nil
	case "kupyna512":
		return nativeDigestProfile{9, 4, 64}, nil
	}
	return nativeDigestProfile{}, errors.New("supported digest profiles: gost34311, kupyna256, kupyna512")
}

func generationKeySpec(bits int) (uint32, error) {
	switch bits {
	case 0, 257:
		return 2, nil
	case 191:
		return 1, nil
	case 307:
		return 3, nil
	}
	return 0, errors.New("supported generated signing key sizes: 191, 257, 307")
}

func generationParameters(family string, bits int) (uint32, uint32, error) {
	if family == "" || family == "gost34311" {
		spec, err := generationKeySpec(bits)
		return 1, spec, err
	}
	if family == "kupyna" {
		spec, err := generationKeySpec(bits)
		return 8, spec, err
	}
	return 0, 0, errors.New("unsupported generated key family/size")
}
