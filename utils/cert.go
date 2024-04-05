package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/rarimo/certificate-transparency-go/x509"
)

// ExtractPubKeys extracts N values of RSA public keys from certificates, which
// can be used for hashing later.
func ExtractPubKeys(certs []*x509.Certificate) ([][]byte, error) {
	pubKeys := make([][]byte, 0, len(certs))
	pkMap := make(map[string]struct{}, len(certs))

	for _, cert := range certs {
		var keyValue *big.Int

		switch key := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			keyValue = key.N
		case *ecdsa.PublicKey:
			// FIXME @violog implement ECDSA support or confirm it to be ignored
			continue
		default:
			return nil, fmt.Errorf("%T: %w", cert.PublicKey, ErrUnsupportedPublicKey)
		}

		if _, ok := pkMap[keyValue.String()]; ok || len(keyValue.Bytes()) == ignoredKeyLength {
			continue
		}

		pkMap[keyValue.String()] = struct{}{}
		pubKeys = append(pubKeys, keyValue.Bytes())
	}

	return pubKeys, nil
}
