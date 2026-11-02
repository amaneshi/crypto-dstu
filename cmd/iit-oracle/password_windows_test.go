package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestNativePasswordEncoding(t *testing.T) {
	for _, tc := range []struct {
		name, password string
		want           []byte
	}{
		{"ASCII", "password", []byte("password\x00")},
		{"Cyrillic", "пароль", []byte{0xef, 0xe0, 0xf0, 0xee, 0xeb, 0xfc, 0}},
		{"Ukrainian", "ЇїЄєҐґ", []byte{0xaf, 0xbf, 0xaa, 0xba, 0xa5, 0xb4, 0}},
		{"empty", "", []byte{0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nativePasswordBytes(tc.password)
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("native password encoding mismatch: %v", err)
			}
		})
	}
	for _, tc := range []struct{ name, password string }{
		{"NUL", "pass\x00word"},
		{"invalid UTF8", "\xff"},
		{"unrepresentable", "emoji\U0001f600"},
		{"oversize", strings.Repeat("a", 65)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := nativePasswordBytes(tc.password); err == nil {
				t.Fatal("lossy/invalid native password accepted")
			}
		})
	}
}
