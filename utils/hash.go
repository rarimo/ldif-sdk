package utils

import (
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/rarimo/certificate-transparency-go/x509"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

const (
	pubKeyLength   = 4096
	chunksAmount   = 64
	subChunkLength = 16 // = len(poseidon.NROUNDSP)
)

var (
	ErrUnsupportedPublicKey = errors.New("unsupported public key, supported formats: rsa")
	ErrInvalidLength        = errors.New("input length must be 4096 bits")
)

// HashCertificate hashes the public key of the certificate, calling PoseidonHash4096
func HashCertificate(certificate *x509.Certificate) (*big.Int, error) {
	rsaPK, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%T: %w", certificate.PublicKey, ErrUnsupportedPublicKey)
	}

	return PoseidonHash4096(rsaPK.N.Bytes())
}

// PoseidonHash4096 hashes 4096 bits of raw data with Poseidon hash function,
// applying splitting data on chunks
func PoseidonHash4096(raw []byte) (*big.Int, error) {
	if len(raw) != pubKeyLength {
		return nil, fmt.Errorf("%w, got %d", ErrInvalidLength, len(raw))
	}

	// split 4096 bits into 64 chunks of 64 bits each
	splitedPubKey := splitBytes(raw)
	hashedChunks := make([]*big.Int, 0, chunksAmount/subChunkLength)

	// on each iteration, hash 16 chunks of 64 bits each
	for i := 0; i < len(splitedPubKey); i += subChunkLength {
		chunks := splitedPubKey[i : i+subChunkLength]
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

// convert bytes from chunkBytes to big integers
func splitBytes(rsaN []byte) []*big.Int {
	chunkedPubKey := chunkBytes(rsaN, len(rsaN)/chunksAmount)

	splitedPubKey := make([]*big.Int, len(chunkedPubKey))
	for i, bytes := range chunkedPubKey {
		splitedPubKey[i] = new(big.Int).SetBytes(bytes)
	}

	return splitedPubKey
}

// divide slice to chunks of size chunkSize
func chunkBytes(data []byte, chunkSize int) [][]byte {
	chunks := make([][]byte, 0, len(data)/chunkSize)

	for chunkSize < len(data) {
		chunks = append(chunks, data[0:chunkSize])
		data = data[chunkSize:]
	}

	return append(chunks, data)
}
