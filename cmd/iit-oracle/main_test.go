package main

import (
	"strings"
	"testing"
)

func TestInvalidRequestsFailBeforeLoadingSDK(t *testing.T) {
	for _, input := range []string{
		`{`,
		`{"operation":"hash","unknown":true}`,
		`{"operation":"hash"} {"operation":"hash"}`,
		`{"operation":"submit-report"}`,
		`{"operation":"verify"}`,
		`{"operation":"hash","digest":"unknown"}`,
		`{"operation":"verify","digest":"kupyna256"}`,
		`{"operation":"hash","key_bits":257}`,
		`{"operation":"generate","key_bits":431,"key_family":"kupyna"}`,
		`{"operation":"generate","key_family":"unknown"}`,
	} {
		t.Run(input, func(t *testing.T) {
			result := run("relative-sdk", strings.NewReader(input))
			if result.OK || result.Error == "" || len(result.Data) > 0 {
				t.Fatalf("unexpected successful result: %+v", result)
			}
		})
	}
}

func TestGenerationProfiles(t *testing.T) {
	for _, family := range []string{"gost34311", "kupyna"} {
		for _, tc := range []struct {
			bits int
			spec uint32
		}{{0, 2}, {191, 1}, {257, 2}, {307, 3}} {
			kind, spec, err := generationParameters(family, tc.bits)
			if err != nil || spec != tc.spec || family == "kupyna" && kind != 8 || family == "gost34311" && kind != 1 {
				t.Fatalf("%s/%d: kind=%d spec=%d error=%v", family, tc.bits, kind, spec, err)
			}
		}
	}
}

func TestDigestAndKeySelectorsFailBeforeSDKLoad(t *testing.T) {
	for _, tc := range []struct{ name, input, message string }{
		{"unsupported digest", `{"operation":"hash","digest":"unknown"}`, "supported digest profiles"},
		{"digest in verify", `{"operation":"verify","digest":"kupyna256"}`, "digest is only valid"},
		{"digest in key-info", `{"operation":"key-info","digest":"gost34311"}`, "digest is only valid"},
		{"empty attached Kupyna512", `{"operation":"sign","digest":"kupyna512"}`, "requires nonempty content"},
		{"ambiguous Kupyna512 certificate", `{"operation":"sign","digest":"kupyna512","data":"eA=="}`, "requires exactly one signer certificate"},
		{"generation size", `{"operation":"generate","key_family":"kupyna","key_bits":431}`, "supported generated signing key sizes"},
		{"generation mode", `{"operation":"hash","key_bits":257}`, "only valid for generate"},
		{"cipher on sign", `{"operation":"sign","cipher":"kalyna256-cfb"}`, "requires static-originator encrypt"},
		{"dynamic explicit cipher", `{"operation":"encrypt","cipher":"kalyna256-cfb"}`, "requires static-originator encrypt"},
		{"unknown cipher", `{"operation":"encrypt","static_originator":true,"cipher":"unknown"}`, "unsupported content cipher"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run("relative-sdk", strings.NewReader(tc.input))
			if result.OK || len(result.Data) != 0 || !strings.Contains(result.Error, tc.message) {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestKupyna512SigningRequestsReachSDKSetup(t *testing.T) {
	for _, input := range []string{
		`{"operation":"sign","digest":"kupyna512","detached":true}`,
		`{"operation":"sign","digest":"kupyna512","data":"eA==","certificates":["eA=="]}`,
	} {
		result := run("relative-sdk", strings.NewReader(input))
		if result.OK || result.Error != "-sdk must be an absolute path" || len(result.Data) != 0 {
			t.Fatalf("unexpected profile selection: %+v", result)
		}
	}
}

func TestTimestampRequirementDoesNotAcceptClaimedTime(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		required, hasSignatureTimestamp, fail bool
	}{
		{"optional absent", false, false, false},
		{"claimed signing time only", true, false, true},
		{"native signature timestamp", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTimestampRequirement(tc.required, tc.hasSignatureTimestamp)
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected timestamp requirement result: %v", err)
			}
		})
	}
	result := run("relative-sdk", strings.NewReader(`{"operation":"hash","require_timestamp":true}`))
	if result.OK || !strings.Contains(result.Error, "only valid for verify") {
		t.Fatalf("unexpected mode result: %v", result.Error)
	}
}
