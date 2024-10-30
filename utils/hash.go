package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/keccak256"
	"github.com/rarimo/certificate-transparency-go/x509"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

// ZKP circuits do not support 768 bytes keys, now there are only 8 keys with this length
const ignoredKeyLength = 768

var ErrUnsupportedPublicKey = errors.New("unsupported public key, supported formats: rsa, ecdsa")

// HashCertificate hashes the public key of the certificate
func HashCertificate(certificate *x509.Certificate) ([]byte, error) {
	var keyValue *big.Int

	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		keyValue = key.N
	case *ecdsa.PublicKey:
		rawKeyBytes := append(key.X.Bytes(), key.Y.Bytes()...)
		keyValue = new(big.Int).SetBytes(rawKeyBytes)
	default:
		return nil, fmt.Errorf("%T: %w", certificate.PublicKey, ErrUnsupportedPublicKey)
	}

	return keccak256.Hash(keyValue.Bytes()), nil
}
