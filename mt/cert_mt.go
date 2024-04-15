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
	for _, certificate := range certificates {
		certHash, err := utils.HashCertificate(certificate)
		if err != nil {
			if errs.Is(err, utils.ErrUnsupportedPublicKey) {
				continue
			}
			return errors.Wrap(err, "failed to hash certificate")
		}

		if certHash == nil {
			continue
		}

		h.tree.Insert(certHash, derivePriority(certHash))
	}

	return nil
}

func (h *certTree) BuildFromRawPK(leaves []string) error {
	for _, leaf := range leaves {
		leafHash, err := utils.PoseidonHashBig([]byte(leaf))
		if err != nil {
			return fmt.Errorf("hash leaf: %w", err)
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

func (h *certTree) GenInclusionProof(certificate *x509.Certificate) (*proof, error) {
	certHash, err := utils.HashCertificate(certificate)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash certificate")
	}

	merklePath, orders := h.tree.MerklePath(certHash)

	return &proof{
		Existence: true,
		Siblings:  merklePath,
		Order:     orders,
	}, nil
}

type proof struct {
	// Existence indicates whether this is a proof of existence or non-existence.
	Existence bool `json:"existence"`
	// Siblings is a list of non-empty sibling hashes.
	Siblings [][]byte `json:"siblings"`
	// Order is an array of hashing order to verify proof:
	//	1. 0 is MustPoseidon(hash, sibling)
	//	2. 1 is MustPoseidon(sibling, hash)
	Order []int `json:"order"`
}
