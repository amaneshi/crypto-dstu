package ua

import (
	"errors"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/transport"
)

// SignOptions controls SignDocument behaviour.
type SignOptions struct {
	Detached bool   // omit content from CMS (detached signature)
	NoTax    bool   // return raw CMS DER; skip transport container wrapping
	Filename string // FILENAME field in transport header
	Email    string // SND_EMAIL field in transport header
}

// SignerResult holds per-signer verification output.
type SignerResult struct {
	CertInfo    *CertInfo
	SigningTime time.Time
	Valid       bool
	Error       error
}

// TimestampResult holds per-timestamp verification output.
type TimestampResult struct {
	Time  time.Time
	Type  string // "signature" or "content"
	Valid bool
	Error error
}

// TransportHeader carries metadata extracted from an Ukrainian tax office transport container.
type TransportHeader struct {
	Filename  string
	SndEmail  string
	RcvEmail  string
	CerType   string
	CRC32Sign string
	CRC32File string
}

// UnsignResult is the output of UnsignDocument.
type UnsignResult struct {
	Content    []byte
	Signers    []SignerResult
	Timestamps []TimestampResult
	Header     *TransportHeader
}

// SignDocument signs content and returns either raw CMS DER (NoTax=true)
// or a transport container (NoTax=false).
func (b *Box) SignDocument(content []byte, opts SignOptions) ([]byte, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.signCert == nil {
		return nil, errors.New("ua: SignDocument: no signing certificate loaded")
	}

	cmsOpts := cms.SignOptions{Detached: opts.Detached}
	cmsDER, err := cms.Sign(content, entry.privateKey, entry.signCert, cmsOpts)
	if err != nil {
		return nil, errors.New("ua: SignDocument: " + err.Error())
	}

	if opts.NoTax {
		return cmsDER, nil
	}

	// Wrap in transport container
	filename := opts.Filename
	if filename == "" {
		filename = defaultFilename
	}

	header := &transport.Header{
		Filename:  filename,
		SndEmail:  opts.Email,
		CerType:   "UA1",
		CRC32Sign: transport.CRC32Hex(cmsDER),
	}
	if !opts.Detached {
		header.CRC32File = transport.CRC32Hex(content)
	}

	container := &transport.Container{
		Header: header,
		Sections: []transport.Section{
			{Label: "UA1_SIGN", Contents: cmsDER},
		},
	}
	return transport.Encode(container), nil
}

// UnsignDocument parses and verifies a signed document.
// Accepts transport container bytes or raw CMS DER.
func (b *Box) UnsignDocument(data []byte) (*UnsignResult, error) {
	result := &UnsignResult{}

	cmsDER := data
	// Try transport container first
	if container, err := transport.Decode(data); err == nil {
		if h := container.Header; h != nil {
			result.Header = &TransportHeader{
				Filename:  h.Filename,
				SndEmail:  h.SndEmail,
				RcvEmail:  h.RcvEmail,
				CerType:   h.CerType,
				CRC32Sign: h.CRC32Sign,
				CRC32File: h.CRC32File,
			}
		}
		// Find a sign section
		for _, label := range []string{"UA_SIGN1", "UA1_SIGN"} {
			if s := container.FindSection(label); s != nil {
				cmsDER = s.Contents
				break
			}
		}
	}

	msg, err := cms.ParseSigned(cmsDER)
	if err != nil {
		return nil, errors.New("ua: UnsignDocument: parse: " + err.Error())
	}

	// If no certs were embedded in the CMS, inject known certs from our Box
	// so that SID matching (issuer+serial) can resolve the signer certificates.
	if len(msg.Certificates) == 0 {
		for _, e := range b.keys {
			if e.signCert != nil {
				msg.Certificates = append(msg.Certificates, e.signCert)
			}
		}
		msg.Certificates = append(msg.Certificates, b.caCerts...)
		cms.ResolveCertificates(msg)
	}

	// Verify signatures (pass caCerts for chain check, nil = skip)
	var roots []*cert.Certificate
	if len(b.caCerts) > 0 {
		roots = b.caCerts
	}
	_ = cms.VerifySigned(msg, nil, roots) // best-effort; errors captured per signer

	result.Content = msg.Content

	for _, sr := range msg.Signers {
		r := SignerResult{
			SigningTime: sr.SigningTime,
			Valid:       sr.Valid,
		}
		if sr.Certificate != nil {
			r.CertInfo = certInfoFromCert(sr.Certificate)
		}
		result.Signers = append(result.Signers, r)
	}

	return result, nil
}
