package ua

import (
	"context"
	"errors"
	"fmt"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/tsp"
)

// TimestampPolicy selects whether signature timestamps participate in acceptance.
type TimestampPolicy int

const (
	// TimestampIgnore preserves document signature verification without TSA claims.
	TimestampIgnore TimestampPolicy = iota
	// TimestampVerifyIfPresent authenticates every supplied signature timestamp.
	TimestampVerifyIfPresent
	// TimestampRequireSignature requires at least one verified token per signer.
	TimestampRequireSignature
)

func (b *Box) checkSignatureTimestamps(ctx context.Context, msg *cms.SignedMessage, options VerificationOptions) ([]TimestampResult, error) {
	var roots []*cert.Certificate
	for _, der := range options.TSARoots {
		c, err := cert.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		roots = append(roots, c)
	}
	var results []TimestampResult
	var failures []error
	for index := range msg.Signers {
		tokens, err := msg.SignatureTimestampTokens(index)
		if err == nil && len(tokens) == 0 && options.TimestampPolicy == TimestampRequireSignature {
			err = errors.New("ua: required signature timestamp is missing")
		}
		if err != nil {
			results = append(results, TimestampResult{SignerIndex: index, Type: "signature", Error: err, RevocationStatus: RevocationNotChecked})
			failures = append(failures, err)
			continue
		}
		signature, err := msg.SignatureBytes(index)
		if err != nil {
			return results, err
		}
		for _, token := range tokens {
			if err := ctx.Err(); err != nil {
				return results, err
			}
			result := TimestampResult{SignerIndex: index, Type: "signature", RevocationStatus: RevocationNotChecked}
			verified, err := tsp.VerifySignatureTimestamp(token, signature, roots, time.Now(), msg.Certificates...)
			if err == nil {
				result.TSA = certInfoFromCert(verified.TSA)
				result.RevocationStatus, err = checkChainRevocation(ctx, verified.Chain, options)
				if err == nil {
					result.Time = verified.Info.GenTime
					result.Valid = true
				}
			}
			result.Error = err
			results = append(results, result)
			if err != nil {
				failures = append(failures, fmt.Errorf("ua: timestamp for signer %d: %w", index, err))
			}
		}
	}
	return results, errors.Join(failures...)
}
