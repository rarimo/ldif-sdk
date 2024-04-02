package mt

import (
	"math/big"

	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/wealdtech/go-merkletree/v2"
)

type CertMT interface {
	BuildTree(certificates []*x509.Certificate) (*merkletree.MerkleTree, error)
	GenInclusionProof(certificate *x509.Certificate) (*merkletree.Proof, error)
	VerifyInclusionProof(certificate *x509.Certificate, proof *merkletree.Proof) (bool, error)
	HashCertificate(certificates *x509.Certificate) (*big.Int, error)
}

func NewCertMT() CertMT {
	return &certMT{
		poseidon16: NewPoseidon(),
		tree:       nil,
	}
}
