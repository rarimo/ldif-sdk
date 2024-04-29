package mt

import (
	errs "errors"
	"fmt"

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
		leafHash, err := utils.PoseidonHashBig(leaf)
		if err != nil {
			if errs.Is(err, utils.ErrInvalidLength) {
				continue
			}
			return fmt.Errorf("hash leaf: %w", err)
		}
		if leafHash == nil {
			continue
		}

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

	merklePath, orders := h.tree.MerklePath(certHash)

	return &Proof{
		Existence: true,
		Siblings:  merklePath,
		Order:     orders,
	}, nil
}

type Proof struct {
	// Existence indicates whether this is a proof of existence or non-existence.
	Existence bool `json:"existence"`
	// Siblings is a list of non-empty sibling hashes.
	Siblings [][]byte `json:"siblings"`
	// Order is an array of hashing order to verify proof:
	//	1. 0 is MustPoseidon(hash, sibling)
	//	2. 1 is MustPoseidon(sibling, hash)
	Order []int `json:"order"`
}
