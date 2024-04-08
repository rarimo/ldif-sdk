package mt

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/rarimo/ldif-sdk/utils"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type certMT interface {
	BuildTree(certificates []*x509.Certificate) (ITreap, error)
	GenInclusionProof(certificate *x509.Certificate) ([][]byte, error)
}

type certTree struct {
	tree ITreap
}

func (h *certTree) BuildTree(certificates []*x509.Certificate) (ITreap, error) {
	h.tree = New()

	for _, certificate := range certificates {
		certHash, err := utils.HashCertificate(certificate)
		if err != nil {
			return nil, errors.Wrap(err, "failed to hash certificate")
		}

		h.tree.Insert(certHash.Bytes(), derivePriority(hexutil.Encode(certHash.Bytes())))
	}

	return h.tree, nil
}

func (h *certTree) BuildFromLeaves(leaves []string) (ITreap, error) {
	h.tree = New()

	for _, leaf := range leaves {
		leafHash, err := utils.PoseidonHashBig([]byte(leaf))
		if err != nil {
			return nil, fmt.Errorf("hash leaf: %w", err)
		}

		h.tree.Insert(leafHash.Bytes(), derivePriority(hexutil.Encode(leafHash.Bytes())))
	}

	return h.tree, nil
}

func (h *certTree) GenInclusionProof(certificate *x509.Certificate) ([][]byte, error) {
	certHash, err := utils.HashCertificate(certificate)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash certificate")
	}

	proof := h.tree.MerklePath(certHash.Bytes())

	return proof, nil
}
