package mt

import (
	"encoding/hex"
	"encoding/json"

	"github.com/rarimo/ldif-sdk/utils"
	"github.com/wealdtech/go-merkletree/v2"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type IncrementalTree struct {
	mTree certMT
}

func BuildTree(elements []string) (*IncrementalTree, error) {
	certificates, err := utils.ParsePemKeys(elements)
	if err != nil {
		return nil, errors.Wrap(err, "failed parse raw pem elements")
	}

	mTree := certMT{
		poseidon: NewPoseidon(),
		tree:     nil,
	}

	_, err = mTree.BuildTree(certificates)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build tree")
	}

	return &IncrementalTree{
		mTree: mTree,
	}, nil
}

func (it IncrementalTree) Root() string {
	return hex.EncodeToString(it.mTree.tree.Root())
}

func (it IncrementalTree) IsExists() bool {
	if it.mTree.tree != nil {
		return true
	}

	return false
}

func (it IncrementalTree) GenerateInclusionProof(rawPemCert string) ([]byte, error) {
	cert, err := utils.ParsePemKey(rawPemCert)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pem key")
	}

	proof, err := it.mTree.GenInclusionProof(cert)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate inclusion proof")
	}

	res, err := json.Marshal(NewInclusionProof(proof))
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal proof")
	}

	return res, nil
}

type InclusionProof struct {
	Hashes []string `json:"hashes"`
	Index  uint64   `json:"index"`
}

func NewInclusionProof(proof *merkletree.Proof) *InclusionProof {
	hashes := make([]string, len(proof.Hashes))
	for i, hash := range proof.Hashes {
		hashes[i] = hex.EncodeToString(hash)
	}

	return &InclusionProof{
		Hashes: hashes,
		Index:  proof.Index,
	}
}
