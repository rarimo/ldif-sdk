package mt

import (
	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/rarimo/ldif-sdk/utils"
	"github.com/wealdtech/go-merkletree/v2"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type CertMT interface {
	BuildTree(certificates []*x509.Certificate) (*merkletree.MerkleTree, error)
	GenInclusionProof(certificate *x509.Certificate) (*merkletree.Proof, error)
	VerifyInclusionProof(certificate *x509.Certificate, proof *merkletree.Proof) (bool, error)
}

type certMT struct {
	poseidon *Poseidon
	tree     *merkletree.MerkleTree
}

func (h *certMT) BuildTree(certificates []*x509.Certificate) (*merkletree.MerkleTree, error) {
	data := make([][]byte, 0)
	for _, certificate := range certificates {
		certHash, err := utils.HashCertificate(certificate)
		if err != nil {
			return nil, errors.Wrap(err, "failed to hash certificate")
		}
		data = append(data, certHash.Bytes())
	}

	var err error
	h.tree, err = merkletree.NewTree(merkletree.WithData(data), merkletree.WithHashType(h.poseidon))
	if err != nil {
		return nil, errors.Wrap(err, "failed build merkle tree")
	}

	return h.tree, nil
}

func (h *certMT) GenInclusionProof(certificate *x509.Certificate) (*merkletree.Proof, error) {
	certHash, err := utils.HashCertificate(certificate)
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
	certHash, err := utils.HashCertificate(certificate)
	if err != nil {
		return false, errors.Wrap(err, "failed to hash certificate")
	}

	proven, err := merkletree.VerifyProofUsing(certHash.Bytes(), false, proof, [][]byte{h.tree.Root()}, h.poseidon)
	if err != nil {
		return false, errors.Wrap(err, "failed to verify proof")
	}

	return proven, nil
}
