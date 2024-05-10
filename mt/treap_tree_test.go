package mt

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var leavesToInsert = []string{
	"9490df6c03b5c8c4f6ac15f66ecb60d4cf69f6eb8ccc939e5260278aa0d12709",
	"e6b17e88388f66064cdc35944187eb5405eada720a9d8cdca24f6c508d9cd245",
	"bbe7408eb7ff72c417cd4b52a561ad9a3357662e8ea649852550f64cace04333",
	"97caed46231f53ce7373beeb905296f257db61dedb44a39cec820c9f1c6fe9bd",
	"480fa52802155f3ebe19b4b00a2ed6363b2c3604eb7905c4096c123712f74ce0",
	"c70c578772fc448a8d9c5f14a13a50a0a87224c68fe7afd2b688da3a504d67fc",
	"19ef3f3bd0fa2bec51048242633eb69c6bae9a7fe66b805ebf7d638d5ffd22be",
	"37c2efa5eede6b5479cd3289c5d37cd29d8c7aa00e964b85ca0e7e00196e786e",
	"cd88a641cca6308c9ff8474c538b3df59dca3eb665eb1b0faee44dcdbaed0ee3",
	"1c7020ea7ca8c94af4bcd7fc8de15a3b842716c487ea528ab05869453771b25f",
	"7425e3f2a4a9590221bacd85c0dec7040d2ec1939e67361f54905d13012fb518",
	"7e565652052881284caf9599af06742d4a03e5ff0e6612efc7ec68476e6ca9dc",
	"e75daac5a045c53f713b3f0e72494f45d41e712f4b9c8c33ca4550eda34f5532",
	"849ce15ec91f20e02cc6cabefde1b9dbb7fb18d7239dba77d578255ed7363357",
	"6809d51a13d958e75dab522670030397e905f674a426e8e3febfd0aea7208941",
	"963ed624c6204df0c10460007147aa945ef528b89560c4ddefe4ebcf1ec8f345",
}

func TestTreap_Insert(t *testing.T) {
	var shouldBeBuilt = []string{
		"bbe7408eb7ff72c417cd4b52a561ad9a3357662e8ea649852550f64cace04333",
		"9490df6c03b5c8c4f6ac15f66ecb60d4cf69f6eb8ccc939e5260278aa0d12709",
		"1c7020ea7ca8c94af4bcd7fc8de15a3b842716c487ea528ab05869453771b25f",
		"19ef3f3bd0fa2bec51048242633eb69c6bae9a7fe66b805ebf7d638d5ffd22be",
		"6809d51a13d958e75dab522670030397e905f674a426e8e3febfd0aea7208941",
		"37c2efa5eede6b5479cd3289c5d37cd29d8c7aa00e964b85ca0e7e00196e786e",
		"480fa52802155f3ebe19b4b00a2ed6363b2c3604eb7905c4096c123712f74ce0",
		"7425e3f2a4a9590221bacd85c0dec7040d2ec1939e67361f54905d13012fb518",
		"7e565652052881284caf9599af06742d4a03e5ff0e6612efc7ec68476e6ca9dc",
		"849ce15ec91f20e02cc6cabefde1b9dbb7fb18d7239dba77d578255ed7363357",
		"97caed46231f53ce7373beeb905296f257db61dedb44a39cec820c9f1c6fe9bd",
		"963ed624c6204df0c10460007147aa945ef528b89560c4ddefe4ebcf1ec8f345",
		"cd88a641cca6308c9ff8474c538b3df59dca3eb665eb1b0faee44dcdbaed0ee3",
		"c70c578772fc448a8d9c5f14a13a50a0a87224c68fe7afd2b688da3a504d67fc",
		"e75daac5a045c53f713b3f0e72494f45d41e712f4b9c8c33ca4550eda34f5532",
		"e6b17e88388f66064cdc35944187eb5405eada720a9d8cdca24f6c508d9cd245",
	}

	treap := buildTreap()
	list := treapToList(treap)
	for i, node := range list {
		assert.Equal(t, shouldBeBuilt[i], node)
	}

	printTree(treap)
}

func TestTreap_Remove(t *testing.T) {
	shouldBeRemoved := []string{
		"97caed46231f53ce7373beeb905296f257db61dedb44a39cec820c9f1c6fe9bd",
		"480fa52802155f3ebe19b4b00a2ed6363b2c3604eb7905c4096c123712f74ce0",
		"c70c578772fc448a8d9c5f14a13a50a0a87224c68fe7afd2b688da3a504d67fc",
		"1c7020ea7ca8c94af4bcd7fc8de15a3b842716c487ea528ab05869453771b25f",
		"7425e3f2a4a9590221bacd85c0dec7040d2ec1939e67361f54905d13012fb518",
		"7e565652052881284caf9599af06742d4a03e5ff0e6612efc7ec68476e6ca9dc",
	}

	shouldBeRemovedMap := make(map[string]struct{}, len(shouldBeRemoved))
	for _, node := range shouldBeRemoved {
		shouldBeRemovedMap[node] = struct{}{}
	}

	shouldRemain := make([]string, 0, len(leavesToInsert)-len(shouldBeRemoved))
	for _, toIns := range leavesToInsert {
		if _, ok := shouldBeRemovedMap[toIns]; !ok {
			shouldRemain = append(shouldRemain, toIns)
		}
	}

	treap := buildTreap()
	for _, toRm := range shouldBeRemoved {
		bytes, _ := hex.DecodeString(toRm)
		treap.Remove(bytes)
	}

	list := treapToList(treap)
	assert.Len(t, list, len(shouldRemain))
	for _, remaining := range shouldRemain {
		assert.Contains(t, list, remaining)
	}

	for _, removed := range shouldBeRemoved {
		assert.NotContains(t, list, removed)
	}

	printTree(treap)
}

func buildTreap() *Treap {
	treap := new(Treap)
	for _, leaf := range leavesToInsert {
		bytes, _ := hex.DecodeString(leaf)
		treap.Insert(bytes, derivePriority(bytes))
	}

	return treap
}

func treapToList(treap *Treap) []string {
	list := make([]string, 0, 16)

	traverse(treap.Root, 0, func(node *Node, _ int) {
		list = append(list, hex.EncodeToString(node.Hash))
	})

	return list
}

func printTree(treap *Treap) {
	fmt.Println("=== Treap ===")

	traverse(treap.Root, 0, func(node *Node, depth int) {
		for i := 0; i < depth; i++ {
			fmt.Print(" ")
		}
		fmt.Println(hex.EncodeToString(node.Hash), node.Priority)
	})

	fmt.Println("=============")
}

func traverse(node *Node, depth int, cb func(*Node, int)) {
	if node == nil {
		return
	}

	cb(node, depth)
	traverse(node.Left, depth+1, cb)
	traverse(node.Right, depth+1, cb)
}
