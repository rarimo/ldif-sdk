package utils

import (
	"crypto/rsa"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/rarimo/certificate-transparency-go/x509"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

const chunksAmount = 64

func HashCertificate(certificate *x509.Certificate) (*big.Int, error) {
	rsaPK, err := ParseCertPublicKey(certificate.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse public key")
	}

	splitedPubKey := splitPublicKey(rsaPK)

	var hashedChunks []*big.Int
	for i := 0; i < len(splitedPubKey); i += 16 {
		chunks := splitedPubKey[i : i+16]
		chunkHash, err := poseidon.Hash(chunks)
		if err != nil {
			return nil, errors.Wrap(err, "failed to hash poseidon 16", logan.F{"chunks": chunks})
		}
		hashedChunks = append(hashedChunks, chunkHash)
	}

	chunkHash, err := poseidon.Hash(hashedChunks)
	if err != nil {
		return nil, errors.Wrap(err, "failed to perform poseidon 4", logan.F{"chunks": hashedChunks})
	}

	return chunkHash, nil
}

func splitPublicKey(rsaPK *rsa.PublicKey) []*big.Int {
	chunkedPubKey := chunkBytes(rsaPK.N.Bytes(), len(rsaPK.N.Bytes())/chunksAmount)
	splitedPubKey := make([]*big.Int, len(chunkedPubKey))
	for i, bytes := range chunkedPubKey {
		splitedPubKey[i] = new(big.Int).SetBytes(bytes)
	}

	return splitedPubKey
}

func chunkBytes(data []byte, chunkSize int) (chunks [][]byte) {
	for chunkSize < len(data) {
		chunks = append(chunks, data[0:chunkSize])
		data = data[chunkSize:]
	}

	return append(chunks, data)
}
