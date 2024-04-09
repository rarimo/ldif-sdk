package mt

import (
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
			return errors.Wrap(err, "failed to hash certificate")
		}

		h.tree.Insert(certHash.Bytes(), derivePriority(certHash.Bytes()))
	}

	return nil
}

func (h *certTree) BuildFromRawPK(leaves []string) error {
	for _, leaf := range leaves {
		leafHash, err := utils.PoseidonHashBig([]byte(leaf))
		if err != nil {
			return fmt.Errorf("hash leaf: %w", err)
		}

		h.tree.Insert(leafHash.Bytes(), derivePriority(leafHash.Bytes()))
	}

	return nil
}

func (h *certTree) BuildFromHashes(leaves [][]byte) error {
	for _, leaf := range leaves {
		h.tree.Insert(leaf, derivePriority(leaf))
	}

	return nil
}

func (h *certTree) GenInclusionProof(certificate *x509.Certificate) ([][]byte, error) {
	certHash, err := utils.HashCertificate(certificate)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash certificate")
	}

	proof := h.tree.MerklePath(certHash.Bytes())

	return proof, nil
}
