package mt

import (
	"crypto/rsa"
	"encoding/hex"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/wealdtech/go-merkletree/v2"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type certMT struct {
	poseidon16 *Poseidon
	tree       *merkletree.MerkleTree
}

const chunksAmount = 64

func (h *certMT) BuildTree(certificates []*x509.Certificate) (*merkletree.MerkleTree, error) {
	data := make([][]byte, 0)
	for _, certificate := range certificates {
		certHash, err := h.HashCertificate(certificate)
		if err != nil {
			return nil, errors.Wrap(err, "failed to hash certificate")
		}
		data = append(data, certHash.Bytes())
	}

	var err error
	h.tree, err = merkletree.NewTree(merkletree.WithData(data), merkletree.WithHashType(h.poseidon16))
	if err != nil {
		return nil, errors.Wrap(err, "failed build merkle tree")
	}

	return h.tree, nil
}

func (h *certMT) GenInclusionProof(certificate *x509.Certificate) (*merkletree.Proof, error) {
	certHash, err := h.HashCertificate(certificate)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash certificate")
	}

	proof, err := h.tree.GenerateProof(certHash.Bytes(), 0)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate merkle tree inclusion proof")
	}

	return proof, nil
}

func (h *certMT) VerifyInclusionProof(certificate *x509.Certificate, proof *merkletree.Proof) (bool, error) {
	certHash, err := h.HashCertificate(certificate)
	if err != nil {
		return false, errors.Wrap(err, "failed to hash certificate")
	}

	proven, err := merkletree.VerifyProofUsing(certHash.Bytes(), false, proof, [][]byte{h.tree.Root()}, h.poseidon16)
	if err != nil {
		return false, errors.Wrap(err, "failed to verify proof")
	}

	return proven, nil
}

func (h *certMT) HashCertificate(certificate *x509.Certificate) (*big.Int, error) {
	rsaPK, err := parsePublicKey(certificate.RawSubjectPublicKeyInfo)
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

func parsePublicKey(rawPK []byte) (*rsa.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(rawPK)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pkix public key", logan.F{
			"raw_pk": hex.EncodeToString(rawPK),
		})
	}
	rsaPK, ok := pk.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA format")
	}

	return rsaPK, nil
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
