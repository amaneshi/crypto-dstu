//go:build integration

package ocsp_test

import (
	"os"
	"path/filepath"
	"testing"

	"crypto-dstu/internal/ocsp"
	"github.com/stretchr/testify/require"
)

// This archived independent fixture checks wire/signature interoperability only;
// its historical certificate status cannot establish current revocation status.
func TestCryptoniteOCSPFixture(t *testing.T) {
	path := filepath.Join("..", "..", "_ref", "cryptonite", "src", "pkixUtest", "resources", "ocsp_resp_for_revoked_cert.dat")
	der, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("optional Cryptonite reference fixture is not installed")
	}
	require.NoError(t, err)
	response, err := ocsp.ParseResponse(der)
	require.NoError(t, err)
	require.NotEmpty(t, response.Certificates)
	require.NoError(t, response.Verify(response.Certificates[0]))
	require.NotEmpty(t, response.Responses)
	require.Equal(t, ocsp.Revoked, response.Responses[0].Status)
}
