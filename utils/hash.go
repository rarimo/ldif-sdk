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
	byteSize       = 64
	chunksAmount   = 64
	subChunkAmount = 16 // = len(poseidon.NROUNDSP)
	// ZKP circuits do not support 768 bits keys, now there are only 8 keys with this length
	ignoredKeyLength = 768
)

var (
	ErrUnsupportedPublicKey = errors.New("unsupported public key, supported formats: rsa")
	ErrInvalidLength        = errors.New("input length must be 256|384|512 bytes")
)

// HashCertificate hashes the public key of the certificate, calling PoseidonHashBig
func HashCertificate(certificate *x509.Certificate) ([]byte, error) {
	rsaPK, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%T: %w", certificate.PublicKey, ErrUnsupportedPublicKey)
	}

	return PoseidonHashBig(rsaPK.N.Bytes())
}

// PoseidonHashBig hashes big raw data (256|384|512 bytes) with Poseidon hash function,
// splitting data on chunks. The most common key length in CSCA list is 512 bytes.
func PoseidonHashBig(raw []byte) ([]byte, error) {
	switch len(raw) {
	case 256, 384, 512:
	case ignoredKeyLength:
		return nil, nil
	default:
		return nil, fmt.Errorf("%w, got %d", ErrInvalidLength, len(raw))
	}

	// split 2048/3072/4096 bits into 64 chunks of 32/48/64 bits each
	splitedPubKey := splitBytes(raw)
	hashedChunks := make([]*big.Int, 0, 4)

	// on each iteration, hash 16 sub-chunks of 32/48/64 bits each
	for i := 0; i < len(splitedPubKey); i += subChunkAmount {
		chunks := splitedPubKey[i : i+subChunkAmount]
		chunkHash, err := poseidon.Hash(chunks)
		if err != nil {
			return nil, errors.Wrap(err, "failed to hash poseidon 16", logan.F{"chunks": chunks})
		}
		hashedChunks = append(hashedChunks, chunkHash)
	}

	// hash 2/3/4 resulting hashes
	chunkHash, err := poseidon.Hash(hashedChunks)
	if err != nil {
		return nil, errors.Wrap(err, "failed to perform poseidon 4", logan.F{"chunks": hashedChunks})
	}

	return To32Bytes(chunkHash.Bytes()), nil
}

func splitBytes(rsaN []byte) []*big.Int {
	return chunkBytes(byteSize, chunksAmount, new(big.Int).SetBytes(rsaN))
}

// chunkBytes splits an `x` N parameter from public key into k chunks amount using
// n as byte size
func chunkBytes(n, k int, x *big.Int) []*big.Int {
	var (
		bigTwo = big.NewInt(2)
		mod    = big.NewInt(1)
		chunks = make([]*big.Int, k)
	)

	for idx := 0; idx < n; idx++ {
		mod = new(big.Int).Mul(mod, bigTwo)
	}

	xTemp := x
	for idx := 0; idx < k; idx++ {
		chunks[idx] = new(big.Int).Mod(xTemp, mod)
		xTemp = new(big.Int).Div(xTemp, mod)
	}

	return chunks
}
