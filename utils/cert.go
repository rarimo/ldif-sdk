package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/rarimo/certificate-transparency-go/x509"
)

// ExtractPubKeys extracts raw data of public keys from certificates, which
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
			rawKeyBytes := append(key.X.Bytes(), key.Y.Bytes()...)
			keyValue = new(big.Int).SetBytes(rawKeyBytes)
		default:
			return nil, fmt.Errorf("%T: %w", cert.PublicKey, ErrUnsupportedPublicKey)
		}

		keyStr, keyBytes := keyValue.String(), keyValue.Bytes()
		if _, ok := pkMap[keyStr]; ok || len(keyBytes) == ignoredKeyLength {
			continue
		}

		pkMap[keyStr] = struct{}{}
		pubKeys = append(pubKeys, keyBytes)
	}

	return pubKeys, nil
}
