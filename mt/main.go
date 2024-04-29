package mt

import (
	"encoding/json"
	"fmt"

	cosmos "github.com/rarimo/ldif-sdk/cosmos/pkg/types"
	"github.com/rarimo/ldif-sdk/utils"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type TreapTree struct {
	mTree *certTree
}

func newTreapTree() *TreapTree {
	return &TreapTree{
		mTree: newCertTree(),
	}
}

// BuildTreeFromMarshalled builds a new dynamic Merkle tree with treap data structure
// from raw pem certificates array marshalled in JSON,
func BuildTreeFromMarshalled(elements []byte) (*TreapTree, error) {
	treapTree := newTreapTree()

	pemKeys := make([]string, 0)
	if err := json.Unmarshal(elements, &pemKeys); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal raw pem keys")
	}

	certificates, err := utils.ParsePemKeys(pemKeys)
	if err != nil {
		return nil, errors.Wrap(err, "failed parse raw pem elements")
	}

	err = treapTree.mTree.BuildFromX509(certificates)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build tree")
	}

	return treapTree, nil
}

// BuildTreeFromCollection builds a new dynamic Merkle tree with treap data structure
// from raw pem certificates, that looks like:
// -----BEGIN CERTIFICATE-----
// ...
// QLIlpAZJZAlpPxwCIFlPFYmq4UcD6I5HJzTUvTRR1oMlYqwBC7SjwtwyspKc
// ...
// -----END CERTIFICATE-----
// -----BEGIN CERTIFICATE-----
// ...
// MIIDKzCCAtCgAwIBAgIII+3Lgsfb3yUwCgYIKoZIzj0EAwIweTEUMBIGA1UEAwwL
func BuildTreeFromCollection(data []byte) (*TreapTree, error) {
	treapTree := newTreapTree()

	certificates, err := utils.ParseCertificatesCollection(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed parse raw pem elements")
	}

	err = treapTree.mTree.BuildFromX509(certificates)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build tree")
	}

	return treapTree, nil
}

// BuildFromRaw builds a new dynamic Merkle tree with treap data structure tree from raw data,
// directly hashing the leaves. It is assumed to use 256|384|512 byte public keys as input.
func BuildFromRaw(leaves []string) (*TreapTree, error) {
	treapTree := newTreapTree()

	rawKeys := make([][]byte, len(leaves))
	for i, leave := range leaves {
		rawKeys[i] = []byte(leave)
	}

	err := treapTree.mTree.BuildFromRawPK(rawKeys)
	if err != nil {
		return nil, fmt.Errorf("build from leaves: %w", err)
	}

	return treapTree, nil
}

// BuildFromCosmos builds a new dynamic Merkle tree with treap data structure by getting elements
// directly from the Cosmos. It requires GRPC Cosmos address with secure flag.
func BuildFromCosmos(addr string, isSecure bool) (*TreapTree, error) {
	treapTree := newTreapTree()

	grpcClient, err := utils.NewGRPCClient(addr, isSecure)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc client: %w", err)
	}

	leaves, err := utils.FetchHashLeavesFromCosmos(cosmos.NewQueryClient(grpcClient))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch leaves from cosmos: %w", err)
	}

	err = treapTree.mTree.BuildFromHashes(leaves)
	if err != nil {
		return nil, fmt.Errorf("failed to build tree from pub key hashes: %w", err)
	}

	return treapTree, nil
}

// Root returns merkle tree root, if there is no tree empty string returned
func (it *TreapTree) Root() []byte {
	if it.mTree.tree == nil || it.mTree.tree.MerkleRoot() == nil {
		return []byte{}
	}

	return it.mTree.tree.MerkleRoot()
}

// IsExists checks if the tree exists
func (it *TreapTree) IsExists() bool {
	if it.mTree.tree != nil || it.mTree.tree.MerkleRoot() != nil {
		return true
	}

	return false
}

// GenerateInclusionProof generates inclusion proof for the given pem certificate,
// returns marshalled inclusion proof type that has boolean existence and bytes array
// of siblings
func (it *TreapTree) GenerateInclusionProof(rawPemCert string) (*Proof, error) {
	cert, err := utils.ParsePemKey(rawPemCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pem key: %w", err)
	}

	incProof, err := it.mTree.GenInclusionProof(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to generate inclusion proof: %w", err)
	}

	return incProof, nil
}
