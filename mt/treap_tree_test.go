package mt

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var leavesToInsert = []string{
	"28815c9a1c9d638886d6ac193df55f98824c491d09bbbd712f96b5adfeba742e",
	"201c77fa8749ec28af53e24913e5bde201e6a7816c0b6e229b9191724ce46a45",
	"27b9c329d9f56b94c3a1d8dc84f2b8e2e0feb636fbc5f6df1474c601e8b979be",
	"022e071cf4eed456dc7f3a36b7b190c6a1f991ef8c5809f612cb193e9c28af78",
	"14d4892218a45bef768d6e148825e647729c4f273a4ec038715c33581e2361e8",
	"08caaaeb4b4b5f589c338c00a7908a5ebae73ff50f3f1a8911f424a476ec7a50",
	"00f032364295f56cb89ad03e1218f35f3f8d1d29ef14f9c457edca6b3555c60f",
	"10e589ae3afb5613bd405d5d0c04c129ab6617e13dad7a2d59e2278dc55aa377",
	"25206c2f6e39dd366f6dfffa8fd80d8e3650bb097797e84b3d13a616f0074243",
	"0d9e5d2c43d671f2f986e9456613ce46fce4bf410950788b8e7584b9eb8f489e",
	"15f19af55d5d29b82570ec8a8cdb79286719e2d11de811da71d6871874365f93",
	"28c6e0e2959d4519185a50e1fc8f37e9ca73be1ce73a620a8f74f13289f76340",
	"2a9951c1901f40491757ba70f024d203361a68083b4d988a3eb876b91f2a9836",
	"0908dce80a5004fe99b125b161d4b3ad596b71744eff190c1cec2aa116a90dd3",
	"19f91688756802bd7f9fa4ca5de2089bb77aa1621c68103800365826945b15b3",
	"1cb29bedc1cac19bcacb59ab2db20b0378e99cb21bec9f3483af1d402aeb5299",
}

func TestTreap_Insert(t *testing.T) {
	var shouldBeBuilt = []string{
		"00f032364295f56cb89ad03e1218f35f3f8d1d29ef14f9c457edca6b3555c60f",
		"27b9c329d9f56b94c3a1d8dc84f2b8e2e0feb636fbc5f6df1474c601e8b979be",
		"0908dce80a5004fe99b125b161d4b3ad596b71744eff190c1cec2aa116a90dd3",
		"022e071cf4eed456dc7f3a36b7b190c6a1f991ef8c5809f612cb193e9c28af78",
		"08caaaeb4b4b5f589c338c00a7908a5ebae73ff50f3f1a8911f424a476ec7a50",
		"0d9e5d2c43d671f2f986e9456613ce46fce4bf410950788b8e7584b9eb8f489e",
		"15f19af55d5d29b82570ec8a8cdb79286719e2d11de811da71d6871874365f93",
		"14d4892218a45bef768d6e148825e647729c4f273a4ec038715c33581e2361e8",
		"10e589ae3afb5613bd405d5d0c04c129ab6617e13dad7a2d59e2278dc55aa377",
		"201c77fa8749ec28af53e24913e5bde201e6a7816c0b6e229b9191724ce46a45",
		"1cb29bedc1cac19bcacb59ab2db20b0378e99cb21bec9f3483af1d402aeb5299",
		"19f91688756802bd7f9fa4ca5de2089bb77aa1621c68103800365826945b15b3",
		"25206c2f6e39dd366f6dfffa8fd80d8e3650bb097797e84b3d13a616f0074243",
		"28815c9a1c9d638886d6ac193df55f98824c491d09bbbd712f96b5adfeba742e",
		"28c6e0e2959d4519185a50e1fc8f37e9ca73be1ce73a620a8f74f13289f76340",
		"2a9951c1901f40491757ba70f024d203361a68083b4d988a3eb876b91f2a9836",
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
		"15f19af55d5d29b82570ec8a8cdb79286719e2d11de811da71d6871874365f93",
		"28815c9a1c9d638886d6ac193df55f98824c491d09bbbd712f96b5adfeba742e",
		"201c77fa8749ec28af53e24913e5bde201e6a7816c0b6e229b9191724ce46a45",
		"27b9c329d9f56b94c3a1d8dc84f2b8e2e0feb636fbc5f6df1474c601e8b979be",
		"022e071cf4eed456dc7f3a36b7b190c6a1f991ef8c5809f612cb193e9c28af78",
		"14d4892218a45bef768d6e148825e647729c4f273a4ec038715c33581e2361e8",
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
	traverse(treap.Root, 0, func(node *Node, depth int) {
		for i := 0; i < depth; i++ {
			fmt.Print(" ")
		}
		fmt.Println(hex.EncodeToString(node.Hash))
	})
}

func traverse(node *Node, depth int, cb func(*Node, int)) {
	if node == nil {
		return
	}

	cb(node, depth)
	traverse(node.Left, depth+1, cb)
	traverse(node.Right, depth+1, cb)
}
