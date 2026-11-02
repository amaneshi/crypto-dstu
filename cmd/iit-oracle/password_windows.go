package main

import (
	"errors"
	"runtime"
	"syscall"
	"unicode/utf8"
	"unsafe"
)

// IIT EUSignMSWCPPAppendixA, section A.4, specifies CP1251 for the Windows
// CHAR/PSTR API. JSON and the Go library use logical UTF-8 strings; convert only
// at the native adapter boundary, rejecting unrepresentable/default characters.
func nativePasswordBytes(password string) ([]byte, error) {
	if !utf8.ValidString(password) {
		return nil, errors.New("native password is not valid UTF-8")
	}
	wide, err := syscall.UTF16FromString(password)
	if err != nil {
		return nil, errors.New("native password contains NUL")
	}
	defer clear(wide)
	if len(wide) == 1 {
		return []byte{0}, nil
	}
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("WideCharToMultiByte")
	var substituted int32
	// WC_NO_BEST_FIT_CHARS prevents distinct Unicode passwords collapsing into
	// an approximate CP1251 representation. The conversion excludes final NUL.
	length, _, callErr := proc.Call(
		1251, 0x400, uintptr(unsafe.Pointer(&wide[0])), uintptr(len(wide)-1),
		0, 0, 0, uintptr(unsafe.Pointer(&substituted)),
	)
	if length == 0 {
		return nil, callErr
	}
	if length > 64 {
		return nil, errors.New("native password exceeds 64 CP1251 bytes")
	}
	encoded := make([]byte, int(length)+1)
	written, _, callErr := proc.Call(
		1251, 0x400, uintptr(unsafe.Pointer(&wide[0])), uintptr(len(wide)-1),
		uintptr(unsafe.Pointer(&encoded[0])), length, 0, uintptr(unsafe.Pointer(&substituted)),
	)
	runtime.KeepAlive(wide)
	runtime.KeepAlive(encoded)
	if written == 0 {
		clear(encoded)
		return nil, callErr
	}
	if substituted != 0 {
		clear(encoded)
		return nil, errors.New("native Windows password cannot be represented in CP1251")
	}
	return encoded, nil
}
