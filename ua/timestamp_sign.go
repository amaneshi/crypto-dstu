package ua

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
)

// TimestampRequest carries only an encoded RFC 3161 request containing the
// signature imprint and nonce. A fetch callback owns its endpoint/network policy.
type TimestampRequest struct{ DER []byte }

// TimestampSignOptions requests a verified signature timestamp before output.
// Nil Fetch uses explicitly configured Box.AddTSP endpoints. RevocationOptions
// accepts only revocation settings; TSA trust is selected through TSARoots.
type TimestampSignOptions struct {
	// IncludeContentTimestamp also obtains an authenticated timestamp over the
	// original content and signs it as a content-time-stamp attribute.
	IncludeContentTimestamp bool
	TSARoots                [][]byte
	ImprintAlgorithm        asn1.ObjectIdentifier // zero selects GOST 34.311
	Fetch                   func(context.Context, TimestampRequest) ([]byte, error)
	RevocationOptions       VerificationOptions
}

func (b *Box) addSignatureTimestamp(ctx context.Context, document []byte, options TimestampSignOptions) ([]byte, error) {
	message, err := cms.ParseSigned(document)
	if err != nil {
		return nil, err
	}
	signature, err := message.SignatureBytes(0)
	if err != nil {
		return nil, err
	}
	token, err := b.requestVerifiedTimestamp(ctx, signature, options)
	if err != nil {
		return nil, err
	}
	timestamped, err := cms.AttachSignatureTimestamp(document, token)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return timestamped, nil
}

func (b *Box) requestVerifiedTimestamp(ctx context.Context, data []byte, options TimestampSignOptions) ([]byte, error) {
	if len(options.TSARoots) == 0 {
		return nil, errors.New("ua: timestamp creation requires explicit TSA trust roots")
	}
	if options.RevocationOptions.TimestampPolicy != TimestampIgnore || len(options.RevocationOptions.TSARoots) > 0 {
		return nil, errors.New("ua: creation RevocationOptions must contain only revocation settings")
	}
	verification, err := options.RevocationOptions.normalized()
	if err != nil {
		return nil, err
	}
	var roots []*cert.Certificate
	for _, der := range options.TSARoots {
		c, err := cert.ParseCertificate(bytes.Clone(der))
		if err != nil {
			return nil, err
		}
		roots = append(roots, c)
	}
	algorithm := options.ImprintAlgorithm
	if len(algorithm) == 0 {
		algorithm = oid.GOST34311
	}
	imprint, err := tsp.HashData(data, algorithm)
	if err != nil {
		return nil, err
	}
	request, err := tsp.NewRequest(imprint, algorithm)
	if err != nil {
		return nil, err
	}
	requestDER, err := request.Marshal()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var response *tsp.Response
	if options.Fetch != nil {
		der, err := options.Fetch(ctx, TimestampRequest{DER: bytes.Clone(requestDER)})
		if err != nil {
			return nil, fmt.Errorf("ua: fetch timestamp: %w", err)
		}
		response, err = tsp.ParseResponse(bytes.Clone(der))
		if err != nil {
			return nil, err
		}
	} else {
		if len(b.tspClients) == 0 {
			return nil, errors.New("ua: timestamp fetch callback or explicit TSP endpoint is required")
		}
		var failures []error
		for _, client := range b.tspClients {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			response, err = client.SendContext(ctx, requestDER)
			if err == nil {
				break
			}
			failures = append(failures, err)
		}
		if response == nil {
			return nil, errors.Join(failures...)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	verified, err := tsp.VerifyResponse(response, request, roots, time.Now(), b.certificates...)
	if err != nil {
		return nil, err
	}
	if _, err := checkChainRevocation(ctx, verified.Chain, verification); err != nil {
		return nil, err
	}
	token, err := response.Token()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return token, nil
}
