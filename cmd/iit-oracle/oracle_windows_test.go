//go:build windows

package main

import (
	"testing"
	"unsafe"
)

func TestNativeTimeInfoLayout(t *testing.T) {
	var info nativeTimeInfo
	if unsafe.Sizeof(info) != 48 || unsafe.Offsetof(info.SignatureTimestampAvailable) != 28 || unsafe.Offsetof(info.SignatureTimestamp) != 32 {
		t.Fatal("EU_TIME_INFO layout differs from the IIT ABI")
	}
}
