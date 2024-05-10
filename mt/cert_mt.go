package mt

import (
	"fmt"

	"github.com/iden3/go-iden3-crypto/keccak256"
	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/rarimo/ldif-sdk/utils"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type certTree struct {
	tree ITreap
}

func newCertTree() *certTree {
	return &certTree{tree: New()}
}

func (h *certTree) BuildFromX509(certificates []*x509.Certificate) error {
	pks, err := utils.ExtractPubKeys(certificates)
	if err != nil {
		return fmt.Errorf("extract public keys from certificates: %w", err)
	}

	return h.BuildFromRawPK(pks)
}

func (h *certTree) BuildFromRawPK(leaves [][]byte) error {
	for _, leaf := range leaves {
		leafHash := keccak256.Hash(leaf)
		h.tree.Insert(leafHash, derivePriority(leafHash))
	}

	return nil
}

func (h *certTree) BuildFromHashes(leaves [][]byte) error {
	for _, leaf := range leaves {
		h.tree.Insert(leaf, derivePriority(leaf))
	}

	return nil
}

func (h *certTree) GenInclusionProof(certificate *x509.Certificate) (*Proof, error) {
	certHash, err := utils.HashCertificate(certificate)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash certificate")
	}

	merklePath := h.tree.MerklePath(certHash)

	return &Proof{Siblings: merklePath}, nil
}

// Proof is a standard Merkle proof. If len(Siblings) == 0, this is proof of non-existence.
type Proof struct {
	// Siblings is a list of non-empty sibling hashes.
	Siblings [][]byte `json:"siblings"`
}
