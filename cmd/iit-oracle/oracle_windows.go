package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// Native layouts follow IIT EUSignMSWCPPAppendixA.doc (18 April 2024).
// BOOL and DWORD remain 32 bits on both Windows architectures.
type ownerInfo struct {
	Filled int32
	Fields [17]*byte
}
type signInfo struct {
	Owner         ownerInfo
	TimeAvailable int32
	Timestamp     int32
	Time          [8]uint16
}
type sdkLibrary struct{ DLL *syscall.DLL }

// EU_TIME_INFO distinguishes a content timestamp or claimed signing time from
// the unsigned signature timestamp. EU_SIGN_INFO.Timestamp describes the former.
type nativeTimeInfo struct {
	Version                         uint32
	TimeAvailable, ContentTimestamp int32
	DataTime                        [8]uint16
	SignatureTimestampAvailable     int32
	SignatureTimestamp              [8]uint16
}

func (s sdkLibrary) signatureTimestampAvailable(signature []byte, index uint32) (bool, error) {
	var info *nativeTimeInfo
	err := s.call("EUGetSignTimeInfo", uintptr(index), 0, ptr(signature), uintptr(len(signature)), uintptr(unsafe.Pointer(&info)))
	if info != nil {
		defer s.release("EUFreeTimeInfo", uintptr(unsafe.Pointer(info)))
	}
	if err != nil {
		return false, err
	}
	return info != nil && info.SignatureTimestampAvailable != 0 && info.SignatureTimestamp[0] != 0, nil
}

func (s sdkLibrary) call(name string, args ...uintptr) error {
	p, err := s.DLL.FindProc(name)
	if err != nil {
		return err
	}
	code, _, _ := p.Call(args...)
	if uint32(code) == 0 {
		return nil
	}
	return &nativeError{Function: name, Code: uint32(code), Description: "see IIT API error code table"}
}
func (s sdkLibrary) release(name string, args ...uintptr) {
	if p, e := s.DLL.FindProc(name); e == nil {
		p.Call(args...)
	}
}
func ptr(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}

func execute(sdk, config string, req request) ([]byte, error) {
	defer func() { runtime.KeepAlive(req); clear(req.PrivateKey) }()
	// This is a disposable process; changing its working directory allows IIT's
	// dynamically loaded auxiliary modules to resolve beside EUSignCP.dll.
	if err := os.Chdir(sdk); err != nil {
		return nil, err
	}
	dll, err := syscall.LoadDLL(filepath.Join(sdk, "EUSignCP.dll"))
	if err != nil {
		return nil, err
	}
	defer dll.Release()
	s := sdkLibrary{DLL: dll}
	for _, r := range config {
		if r > 127 {
			return nil, errors.New("IIT ANSI interface requires an ASCII temporary path")
		}
	}
	configZ, _ := syscall.ByteSliceFromString(config)
	empty := []byte{0}
	uiMode, err := dll.FindProc("EUSetUIMode")
	if err != nil {
		return nil, err
	}
	uiMode.Call(0)
	if err = s.call("EUSetSettingsFilePath", ptr(configZ)); err != nil {
		return nil, err
	}
	if err = s.call("EUInitialize"); err != nil {
		return nil, err
	}
	defer s.release("EUFinalize")
	zero := uint32(0)
	parameter := []byte("SaveSettings\x00")
	if err = s.call("EUSetRuntimeParameter", ptr(parameter), uintptr(unsafe.Pointer(&zero)), 4); err != nil {
		return nil, err
	}
	settings := []struct {
		Name string
		Args []uintptr
	}{
		{"EUSetModeSettings", []uintptr{1}},
		{"EUSetFileStoreSettings", []uintptr{ptr(configZ), 0, 0, 0, 0, 0, 0, 0}},
		{"EUSetProxySettings", []uintptr{0, 1, ptr(empty), ptr(empty), ptr(empty), ptr(empty), 0}},
		{"EUSetOCSPSettings", []uintptr{0, 0, ptr(empty), ptr(empty)}},
		{"EUSetTSPSettings", []uintptr{0, ptr(empty), ptr(empty)}},
		{"EUSetLDAPSettings", []uintptr{0, ptr(empty), ptr(empty), 1, ptr(empty), ptr(empty)}},
		{"EURefreshFileStore", []uintptr{1}},
	}
	for _, setting := range settings {
		if err = s.call(setting.Name, setting.Args...); err != nil {
			return nil, err
		}
	}
	runtime.KeepAlive(configZ)
	runtime.KeepAlive(empty)
	runtime.KeepAlive(parameter)
	for _, c := range req.Certificates {
		if len(c) == 0 {
			return nil, errors.New("empty test certificate")
		}
		err = s.call("EUSaveCertificate", ptr(c), uintptr(len(c)))
		runtime.KeepAlive(c)
		if err != nil {
			return nil, err
		}
	}
	if req.Digest != "" {
		return s.executeDigestProfile(req)
	}
	if req.Operation == "generate" {
		var media struct {
			Type, Device uint32
			Password     [65]byte
		}
		encodedPassword, err := nativePasswordBytes(req.Password)
		if err != nil {
			return nil, err
		}
		defer clear(encodedPassword)
		if len(encodedPassword) == 1 {
			return nil, errors.New("test password must be 1..64 bytes")
		}
		copy(media.Password[:], encodedPassword)
		defer clear(media.Password[:])
		var outputs [3]*byte
		var lengths [3]uint32
		defer func() {
			for _, p := range outputs {
				if p != nil {
					s.release("EUFreeMemory", uintptr(unsafe.Pointer(p)))
				}
			}
		}()
		var filename [1024]byte
		keyType, keySpec, specErr := generationParameters(req.KeyFamily, req.KeyBits)
		if specErr != nil {
			return nil, specErr
		}
		err = s.call("EUGeneratePrivateKeyEx", uintptr(unsafe.Pointer(&media)), 0, uintptr(keyType), uintptr(keySpec), 0, 0, 0, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(&outputs[0])), uintptr(unsafe.Pointer(&lengths[0])),
			uintptr(unsafe.Pointer(&outputs[1])), uintptr(unsafe.Pointer(&lengths[1])),
			uintptr(unsafe.Pointer(&outputs[2])), uintptr(unsafe.Pointer(&lengths[2])), uintptr(unsafe.Pointer(&filename[0])),
			0, 0, 0, 0, 0, 0)
		runtime.KeepAlive(media)
		if err != nil {
			return nil, err
		}
		if lengths[0] == 0 || lengths[0] > 8<<20 || outputs[0] == nil {
			return nil, errors.New("invalid generated key length")
		}
		return bytes.Clone(unsafe.Slice(outputs[0], lengths[0])), nil
	}
	if req.Operation == "sign" || req.Operation == "decrypt" || req.Operation == "encrypt" && req.StaticOriginator {
		if len(req.PrivateKey) == 0 {
			return nil, errors.New("disposable test key is required")
		}
		password, err := nativePasswordBytes(req.Password)
		if err != nil {
			return nil, err
		}
		defer clear(password)
		var owner ownerInfo
		err = s.call("EUReadPrivateKeyBinary", ptr(req.PrivateKey), uintptr(len(req.PrivateKey)), ptr(password), uintptr(unsafe.Pointer(&owner)))
		runtime.KeepAlive(req.PrivateKey)
		runtime.KeepAlive(password)
		s.release("EUFreeCertOwnerInfo", uintptr(unsafe.Pointer(&owner)))
		if err != nil {
			return nil, err
		}
		defer s.release("EUResetPrivateKey")
	}
	var output *byte
	var length uint32
	defer func() {
		if output != nil {
			s.release("EUFreeMemory", uintptr(unsafe.Pointer(output)))
		}
	}()
	if req.Operation == "key-info" {
		if len(req.PrivateKey) == 0 {
			return nil, errors.New("disposable test key is required")
		}
		password, passwordErr := nativePasswordBytes(req.Password)
		if passwordErr != nil {
			return nil, passwordErr
		}
		defer clear(password)
		err = s.call(
			"EUGetKeyInfoBinary",
			ptr(req.PrivateKey), uintptr(len(req.PrivateKey)), ptr(password),
			uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&length)),
		)
		runtime.KeepAlive(password)
	} else if req.Operation == "hash" {
		input := req.Data
		if len(input) == 0 {
			input = []byte{0}
		}
		err = s.call("EUHashData", ptr(input), uintptr(len(req.Data)), 0, uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&length)))
		runtime.KeepAlive(input)
	} else if req.Operation == "sign" {
		if req.Detached {
			err = s.call("EUSignData", ptr(req.Data), uintptr(len(req.Data)), 0, uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&length)))
		} else {
			err = s.call("EUSignDataInternal", 1, ptr(req.Data), uintptr(len(req.Data)), 0, uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&length)))
		}
	} else if req.Operation == "encrypt" {
		if len(req.Recipients) == 0 || len(req.Recipients) > 64 {
			return nil, errors.New("1..64 recipients required")
		}
		certs := make([]*byte, len(req.Recipients))
		sizes := make([]uint32, len(req.Recipients))
		for i, c := range req.Recipients {
			if len(c) == 0 {
				return nil, errors.New("empty recipient certificate")
			}
			certs[i] = &c[0]
			sizes[i] = uint32(len(c))
		}
		if req.Cipher != "" {
			algorithm := uintptr(9)
			if req.Cipher == "kalyna256-ofb" {
				algorithm = 8
			}
			err = s.call(
				"EUEnvelopDataToRecipientsWithSettingsEx",
				algorithm,
				uintptr(len(certs)),
				uintptr(unsafe.Pointer(&certs[0])),
				uintptr(unsafe.Pointer(&sizes[0])),
				0,
				ptr(req.Data),
				uintptr(len(req.Data)),
				1,
				1,
				1,
				1,
				0,
				uintptr(unsafe.Pointer(&output)),
				uintptr(unsafe.Pointer(&length)),
			)
		} else if req.StaticOriginator {
			err = s.call("EUEnvelopDataToRecipientsOffline", uintptr(len(certs)), uintptr(unsafe.Pointer(&certs[0])), uintptr(unsafe.Pointer(&sizes[0])), 0, ptr(req.Data), uintptr(len(req.Data)), 1, 1, 0, uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&length)))
		} else {
			err = s.call("EUEnvelopDataToRecipientsWithDynamicKey", uintptr(len(certs)), uintptr(unsafe.Pointer(&certs[0])), uintptr(unsafe.Pointer(&sizes[0])), 0, 0, ptr(req.Data), uintptr(len(req.Data)), 0, uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&length)))
		}
		runtime.KeepAlive(certs)
		runtime.KeepAlive(sizes)
	} else if req.Operation == "decrypt" {
		var info signInfo // EU_ENVELOP_INFO has the same owner/time layout.
		err = s.call("EUDevelopData", 0, ptr(req.Data), uintptr(len(req.Data)), uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&length)), uintptr(unsafe.Pointer(&info)))
		s.release("EUFreeEnvelopInfo", uintptr(unsafe.Pointer(&info)))
	} else {
		if len(req.Signature) == 0 {
			return nil, errors.New("signature is required")
		}
		var count uint32
		err = s.call("EUGetSignsCount", 0, ptr(req.Signature), uintptr(len(req.Signature)), uintptr(unsafe.Pointer(&count)))
		if err != nil {
			return nil, err
		}
		if count == 0 || count > 64 {
			return nil, fmt.Errorf("invalid signer count %d", count)
		}
		for i := uint32(0); i < count; i++ {
			var info signInfo
			if req.Detached {
				err = s.call("EUVerifyDataOnTimeEx", ptr(req.Data), uintptr(len(req.Data)), uintptr(i), 0, ptr(req.Signature), uintptr(len(req.Signature)), 0, 1, 1, uintptr(unsafe.Pointer(&info)))
			} else {
				var part *byte
				var size uint32
				err = s.call("EUVerifyDataInternalOnTimeEx", uintptr(i), 0, ptr(req.Signature), uintptr(len(req.Signature)), 0, 1, 1, uintptr(unsafe.Pointer(&part)), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&info)))
				if part != nil {
					if size > 8<<20 {
						err = errors.New("IIT output exceeds limit")
					}
					if err == nil && size <= 8<<20 {
						if output == nil {
							output = part
							length = size
							part = nil
						} else if !bytes.Equal(unsafe.Slice(output, length), unsafe.Slice(part, size)) {
							err = errors.New("inconsistent signed content")
						}
					}
					if part != nil {
						s.release("EUFreeMemory", uintptr(unsafe.Pointer(part)))
					}
				}
			}
			if err == nil && req.RequireTimestamp {
				available, infoErr := s.signatureTimestampAvailable(req.Signature, i)
				if infoErr != nil {
					err = infoErr
				} else {
					err = checkTimestampRequirement(true, available)
				}
			}
			s.release("EUFreeSignInfo", uintptr(unsafe.Pointer(&info)))
			if err != nil {
				return nil, err
			}
		}
		if req.Detached {
			return bytes.Clone(req.Data), nil
		}
	}
	runtime.KeepAlive(req)
	if err != nil {
		return nil, err
	}
	if length > 8<<20 || output == nil && length != 0 {
		return nil, errors.New("invalid IIT output length")
	}
	return bytes.Clone(unsafe.Slice(output, length)), nil
}

// Context APIs select the signature/hash algorithm explicitly. Each context and
// its outputs are owned by this one disposable process and released in order.
func (s sdkLibrary) executeDigestProfile(req request) ([]byte, error) {
	profile, err := digestProfile(req.Digest)
	if err != nil {
		return nil, err
	}
	var ctx uintptr
	if err := s.call("EUCtxCreate", uintptr(unsafe.Pointer(&ctx))); err != nil {
		return nil, err
	}
	defer s.release("EUCtxFree", ctx)
	var private uintptr
	if req.Operation == "sign" {
		if len(req.PrivateKey) == 0 {
			return nil, errors.New("disposable test key is required")
		}
		password, err := nativePasswordBytes(req.Password)
		if err != nil {
			return nil, err
		}
		defer clear(password)
		var owner ownerInfo
		err = s.call("EUCtxReadPrivateKeyBinary", ctx, ptr(req.PrivateKey), uintptr(len(req.PrivateKey)), ptr(password), uintptr(unsafe.Pointer(&private)), uintptr(unsafe.Pointer(&owner)))
		s.release("EUCtxFreeCertOwnerInfo", ctx, uintptr(unsafe.Pointer(&owner)))
		if private != 0 {
			defer s.release("EUCtxFreePrivateKey", private)
		}
		if err != nil {
			return nil, err
		}
	}
	var output *byte
	var length uint32
	defer func() {
		if output != nil {
			s.release("EUCtxFreeMemory", ctx, uintptr(unsafe.Pointer(output)))
		}
	}()
	data := req.Data
	if len(data) == 0 {
		data = []byte{0}
	}
	if req.Operation == "hash" {
		err = s.call("EUCtxHashData", ctx, uintptr(profile.Hash), 0, 0, ptr(data), uintptr(len(req.Data)), uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&length)))
	} else if req.Digest == "kupyna512" {
		var hash *byte
		var hashLength uint32
		defer func() {
			if hash != nil {
				s.release("EUCtxFreeMemory", ctx, uintptr(unsafe.Pointer(hash)))
			}
		}()
		// The hash length selects Kupyna-512; EUCtxSignData defaults to 256.
		err = s.call(
			"EUCtxHashData",
			ctx,
			uintptr(profile.Hash),
			0,
			0,
			ptr(data),
			uintptr(len(req.Data)),
			uintptr(unsafe.Pointer(&hash)),
			uintptr(unsafe.Pointer(&hashLength)),
		)
		if err != nil {
			return nil, err
		}
		if hash == nil || int(hashLength) != profile.Size {
			return nil, errors.New("invalid native hash length")
		}
		if req.Detached {
			err = s.call(
				"EUCtxSignHashValue",
				private,
				uintptr(profile.Sign),
				uintptr(unsafe.Pointer(hash)),
				uintptr(hashLength),
				1,
				uintptr(unsafe.Pointer(&output)),
				uintptr(unsafe.Pointer(&length)),
			)
		} else {
			if len(req.Certificates) != 1 {
				return nil, errors.New("Kupyna512 attached signing requires exactly one signer certificate")
			}
			var signer, empty *byte
			var signerLength, emptyLength uint32
			defer func() {
				for _, p := range []*byte{signer, empty} {
					if p != nil {
						s.release("EUCtxFreeMemory", ctx, uintptr(unsafe.Pointer(p)))
					}
				}
			}()
			err = s.call(
				"EUCtxCreateSigner",
				private,
				uintptr(profile.Sign),
				uintptr(unsafe.Pointer(hash)),
				uintptr(hashLength),
				uintptr(unsafe.Pointer(&signer)),
				uintptr(unsafe.Pointer(&signerLength)),
			)
			if err != nil {
				return nil, err
			}
			if signer == nil || signerLength == 0 || signerLength > 8<<20 {
				return nil, errors.New("invalid native signer length")
			}
			certificate := req.Certificates[0]
			err = s.call(
				"EUCtxCreateEmptySign",
				ctx,
				uintptr(profile.Sign),
				ptr(data),
				uintptr(len(req.Data)),
				ptr(certificate),
				uintptr(len(certificate)),
				uintptr(unsafe.Pointer(&empty)),
				uintptr(unsafe.Pointer(&emptyLength)),
			)
			if err != nil {
				return nil, err
			}
			if empty == nil || emptyLength == 0 || emptyLength > 8<<20 {
				return nil, errors.New("invalid native empty signature length")
			}
			err = s.call(
				"EUCtxAppendSigner",
				ctx,
				uintptr(profile.Sign),
				uintptr(unsafe.Pointer(signer)),
				uintptr(signerLength),
				ptr(certificate),
				uintptr(len(certificate)),
				uintptr(unsafe.Pointer(empty)),
				uintptr(emptyLength),
				uintptr(unsafe.Pointer(&output)),
				uintptr(unsafe.Pointer(&length)),
			)
		}
	} else {
		external := uintptr(0)
		if req.Detached {
			external = 1
		}
		err = s.call("EUCtxSignData", private, uintptr(profile.Sign), ptr(data), uintptr(len(req.Data)), external, 1, uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&length)))
	}
	runtime.KeepAlive(req)
	runtime.KeepAlive(data)
	if err != nil {
		return nil, err
	}
	if output == nil || length == 0 || length > 8<<20 {
		return nil, errors.New("invalid native profile output length")
	}
	if req.Operation == "hash" && int(length) != profile.Size {
		return nil, errors.New("native hash size differs from requested profile")
	}
	result := bytes.Clone(unsafe.Slice(output, length))
	if req.Operation == "sign" {
		if err := checkNativeSigningProfile(result, req.Digest, req.Detached); err != nil {
			return nil, err
		}
	}
	return result, nil
}
