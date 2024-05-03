package mt

import (
	"bytes"
	"math"
	"math/big"

	"github.com/iden3/go-iden3-crypto/keccak256"
)

const TreeHeight = 16

type Node struct {
	Hash        []byte
	Priority    uint64
	MerkleHash  []byte
	Left, Right *Node
}

type ITreap interface {
	Remove(key []byte)
	Insert(key []byte, priority uint64)
	MerklePath(key []byte) [][]byte
	MerkleRoot() []byte
}

type Treap struct {
	Root *Node
}

// Implements ITreap
var _ ITreap = &Treap{}

func New() ITreap {
	return &Treap{}
}

func (t *Treap) Remove(key []byte) {
	if t.Root == nil {
		return
	}
	// Split the tree by key-1 => target key in the right subtree
	// Split the subtree by key => target key is one left node
	keyBig := new(big.Int).SetBytes(key)
	keySub1 := new(big.Int).Sub(keyBig, big.NewInt(1)).Bytes()

	left, right := split(t.Root, keySub1)
	if right == nil {
		return
	}

	_, right = split(right, key)
	t.Root = merge(left, right)
}

func (t *Treap) Insert(key []byte, priority uint64) {
	middle := &Node{
		Hash:       key,
		MerkleHash: key,
		Priority:   priority,
	}

	if t.Root == nil {
		t.Root = middle
		return
	}

	left, right := split(t.Root, key)
	t.Root = merge(merge(left, middle), right)
}

func (t *Treap) MerklePath(key []byte) [][]byte {
	node := t.Root
	result := make([][]byte, 0, TreeHeight)

	for node != nil {
		if bytes.Compare(node.Hash, key) == 0 {
			result = append(result, hashNodes(node.Left, node.Right))
			reverseSlice(result)
			return result
		}

		if bytes.Compare(node.Hash, key) > 0 {
			result = append(result, node.Hash)
			if node.Right != nil {
				result = append(result, node.Right.MerkleHash)
			}
			node = node.Left
			continue
		}

		result = append(result, node.Hash)
		if node.Left != nil {
			result = append(result, node.Left.MerkleHash)
		}
		node = node.Right
	}

	return nil
}

func (t *Treap) MerkleRoot() []byte {
	if t.Root == nil {
		return nil
	}

	return t.Root.MerkleHash
}

func split(root *Node, key []byte) (*Node, *Node) {
	if root == nil {
		return nil, nil
	}

	// Removal implementation relies on '<= 0'
	if bytes.Compare(root.Hash, key) <= 0 {
		left, right := split(root.Right, key)
		root.Right = left
		updateNode(root)
		return root, right
	}

	left, right := split(root.Left, key)
	root.Left = right
	updateNode(root)
	return left, root
}

func merge(left, right *Node) *Node {
	if left == nil {
		return right
	}

	if right == nil {
		return left
	}

	if left.Priority > right.Priority {
		left.Right = merge(left.Right, right)
		updateNode(left)
		return left
	}

	right.Left = merge(left, right.Left)
	updateNode(right)
	return right
}

func updateNode(node *Node) {
	childrenHash := hashNodes(node.Left, node.Right)
	if childrenHash == nil {
		node.MerkleHash = node.Hash
		return
	}

	node.MerkleHash = hash(childrenHash, node.Hash)
}

func hashNodes(a, b *Node) []byte {
	var left, right []byte

	if a != nil {
		left = a.MerkleHash
	}

	if b != nil {
		right = b.MerkleHash
	}

	return hash(left, right)
}

// priority = keccak256.Hash(key) % (2^64-1)
func derivePriority(key []byte) uint64 {
	var (
		keyHash = new(big.Int).SetBytes(keccak256.Hash(key))
		u64     = new(big.Int).SetUint64(math.MaxUint64)
	)

	return keyHash.Mod(keyHash, u64).Uint64()
}

func hash(a, b []byte) []byte {
	if len(a) == 0 {
		return b
	}

	if len(b) == 0 {
		return a
	}

	if bytes.Compare(a, b) < 0 {
		return keccak256.Hash(a, b)
	}

	return keccak256.Hash(b, a)
}

func reverseSlice[S ~[]E, E any](s S) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
