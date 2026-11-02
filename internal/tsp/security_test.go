package tsp

import (
	"crypto-dstu/internal/cert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTimestampRejectsCorruptedSignatureAndMissingTrust(t *testing.T) {
	key := mustGenerateKey(t)
	tsa := makeCert(t, key)
	hash := hashKupyna256([]byte("timestamped document"))
	token := buildSampleToken(t, key, tsa, hash, nil)
	_, err := VerifyToken(token, hash, nil, nil)
	require.Error(t, err)
	token[len(token)-1] ^= 1
	_, err = VerifyToken(token, hash, nil, []*cert.Certificate{tsa})
	require.Error(t, err)
}
