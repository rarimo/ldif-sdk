package utils

import (
	"crypto/rsa"
	"fmt"

	"github.com/rarimo/certificate-transparency-go/x509"
)

// ExtractPubKeys extracts N values of RSA public keys from certificates, which
// can be used for hashing later.
func ExtractPubKeys(certs []*x509.Certificate) ([][]byte, error) {
	pubKeys := make([][]byte, 0, len(certs))
	pkMap := make(map[string]struct{}, len(certs))

	for _, cert := range certs {
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%T: %w", cert.PublicKey, ErrUnsupportedPublicKey)
		}

		if _, ok = pkMap[key.N.String()]; ok {
			continue
		}

		pkMap[key.N.String()] = struct{}{}
		pubKeys = append(pubKeys, key.N.Bytes())
	}

	return pubKeys, nil
}
