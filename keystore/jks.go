package keystore

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// JKS magic number and supported version.
const (
	jksMagic   = 0xFEEDFEED
	jksVersion = 2
)

// JKSEntry represents a single key entry from a Java KeyStore.
type JKSEntry struct {
	Alias     string
	KeyDER    []byte   // raw DER-encoded encrypted private key (needs further decryption)
	CertChain [][]byte // DER-encoded X.509 certificates
}

// Role constants for JKS entries used in PrivatBank-style keystores.
type Role string

const (
	RolePersonal Role = "personal"
	RoleFOP      Role = "fop"
	RoleDirector Role = "director"
	RoleStamp    Role = "stamp"
	RoleOther    Role = "other"
)

// ParseJKS parses a Java KeyStore binary blob and returns all key entries.
// The returned JKSEntry.KeyDER contains the raw encrypted key data; use
// DecryptJKSKey to decrypt an individual entry's private key.
//
// JKS binary format (big-endian):
//
//	magic        uint32 = 0xFEEDFEED
//	version      uint32 = 2
//	count        uint32
//	For each entry:
//	    tag      uint32  (1=key, 2=cert)
//	    alias    utf8    (uint16 length prefix)
//	    stamp    int64   (millis since epoch — ignored)
//	    For tag=1:
//	        key_count  uint32 (always 1 for single key)
//	        key_data   length-prefixed OCTET STRING
//	        cert_count uint32
//	        For each cert:
//	            cert_type length-prefixed UTF8
//	            cert_data length-prefixed bytes
//	    For tag=2:
//	        cert_type length-prefixed UTF8
//	        cert_data length-prefixed bytes
//
// Reference: dstucrypt/jksreader parse.js + pavlo-v-chernykh/keystore-go
func ParseJKS(data []byte) ([]JKSEntry, error) {
	r := &byteReader{b: data}

	magic, err := r.readUint32()
	if err != nil || magic != jksMagic {
		return nil, errors.New("keystore: JKS: invalid magic")
	}
	version, err := r.readUint32()
	if err != nil {
		return nil, errors.New("keystore: JKS: truncated header")
	}
	if version != jksVersion {
		return nil, errors.New("keystore: JKS: unsupported version")
	}
	count, err := r.readUint32()
	if err != nil {
		return nil, errors.New("keystore: JKS: truncated entry count")
	}

	entries := make([]JKSEntry, 0, count)

	for i := uint32(0); i < count; i++ {
		tag, err := r.readUint32()
		if err != nil {
			return nil, errors.New("keystore: JKS: truncated tag")
		}

		alias, err := r.readUTF()
		if err != nil {
			return nil, errors.New("keystore: JKS: truncated alias")
		}

		// Skip 8-byte timestamp
		if err := r.skip(8); err != nil {
			return nil, errors.New("keystore: JKS: truncated timestamp")
		}

		switch tag {
		case 1: // key entry
			entry, err := parseJKSKeyEntry(r, alias)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)

		case 2: // trusted certificate entry — store nothing, skip
			if err := skipJKSCert(r); err != nil {
				return nil, err
			}

		default:
			return nil, errors.New("keystore: JKS: unknown tag")
		}
	}

	return entries, nil
}

func parseJKSKeyEntry(r *byteReader, alias string) (JKSEntry, error) {
	// Number of keys (always 1 for PKCS8 JKS)
	keyCount, err := r.readUint32()
	if err != nil {
		return JKSEntry{}, errors.New("keystore: JKS: truncated key count")
	}
	if keyCount != 1 {
		return JKSEntry{}, errors.New("keystore: JKS: unexpected key count")
	}

	keyData, err := r.readLenBytes()
	if err != nil {
		return JKSEntry{}, errors.New("keystore: JKS: truncated key data")
	}

	// Read cert chain
	certCount, err := r.readUint32()
	if err != nil {
		return JKSEntry{}, errors.New("keystore: JKS: truncated cert count")
	}

	certs := make([][]byte, 0, certCount)
	for j := uint32(0); j < certCount; j++ {
		// cert type string (e.g. "X.509")
		if _, err := r.readUTF(); err != nil {
			return JKSEntry{}, errors.New("keystore: JKS: truncated cert type")
		}
		certData, err := r.readLenBytes()
		if err != nil {
			return JKSEntry{}, errors.New("keystore: JKS: truncated cert data")
		}
		certs = append(certs, certData)
	}

	return JKSEntry{
		Alias:     alias,
		KeyDER:    keyData,
		CertChain: certs,
	}, nil
}

func skipJKSCert(r *byteReader) error {
	if _, err := r.readUTF(); err != nil {
		return errors.New("keystore: JKS: truncated trusted cert type")
	}
	if _, err := r.readLenBytes(); err != nil {
		return errors.New("keystore: JKS: truncated trusted cert data")
	}
	return nil
}

// FindByRole returns the first JKS entry whose alias contains the role string
// (case-insensitive). For PrivatBank JKS files the alias names typically
// indicate role: "stamp", "director", "personal", etc.
func FindByRole(entries []JKSEntry, role Role) *JKSEntry {
	needle := strings.ToLower(string(role))
	for i := range entries {
		if strings.Contains(strings.ToLower(entries[i].Alias), needle) {
			return &entries[i]
		}
	}
	return nil
}

// byteReader is a simple sequential byte reader over a fixed buffer.
type byteReader struct {
	b   []byte
	pos int
}

func (r *byteReader) remaining() int { return len(r.b) - r.pos }

func (r *byteReader) readN(n int) ([]byte, error) {
	if r.remaining() < n {
		return nil, io.ErrUnexpectedEOF
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *byteReader) skip(n int) error {
	_, err := r.readN(n)
	return err
}

func (r *byteReader) readUint16() (uint16, error) {
	b, err := r.readN(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *byteReader) readUint32() (uint32, error) {
	b, err := r.readN(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// readUTF reads a Java-style modified UTF-8 string (2-byte length, then UTF-8 bytes).
func (r *byteReader) readUTF() (string, error) {
	length, err := r.readUint16()
	if err != nil {
		return "", err
	}
	b, err := r.readN(int(length))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// readLenBytes reads a uint32-prefixed byte slice.
func (r *byteReader) readLenBytes() ([]byte, error) {
	length, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	data, err := r.readN(int(length))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}
