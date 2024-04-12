package mt

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

var leavesToInsert = []string{
	"0x28815c9a1c9d638886d6ac193df55f98824c491d09bbbd712f96b5adfeba742e",
	"0x201c77fa8749ec28af53e24913e5bde201e6a7816c0b6e229b9191724ce46a45",
	"0x27b9c329d9f56b94c3a1d8dc84f2b8e2e0feb636fbc5f6df1474c601e8b979be",
	"0x022e071cf4eed456dc7f3a36b7b190c6a1f991ef8c5809f612cb193e9c28af78",
	"0x14d4892218a45bef768d6e148825e647729c4f273a4ec038715c33581e2361e8",
	"0x08caaaeb4b4b5f589c338c00a7908a5ebae73ff50f3f1a8911f424a476ec7a50",
	"0x00f032364295f56cb89ad03e1218f35f3f8d1d29ef14f9c457edca6b3555c60f",
	"0x10e589ae3afb5613bd405d5d0c04c129ab6617e13dad7a2d59e2278dc55aa377",
	"0x25206c2f6e39dd366f6dfffa8fd80d8e3650bb097797e84b3d13a616f0074243",
	"0x0d9e5d2c43d671f2f986e9456613ce46fce4bf410950788b8e7584b9eb8f489e",
	"0x15f19af55d5d29b82570ec8a8cdb79286719e2d11de811da71d6871874365f93",
	"0x28c6e0e2959d4519185a50e1fc8f37e9ca73be1ce73a620a8f74f13289f76340",
	"0x2a9951c1901f40491757ba70f024d203361a68083b4d988a3eb876b91f2a9836",
	"0x0908dce80a5004fe99b125b161d4b3ad596b71744eff190c1cec2aa116a90dd3",
	"0x19f91688756802bd7f9fa4ca5de2089bb77aa1621c68103800365826945b15b3",
	"0x1cb29bedc1cac19bcacb59ab2db20b0378e99cb21bec9f3483af1d402aeb5299",
}

func TestTreap_Insert(t *testing.T) {
	var shouldBeBuilt = []string{
		"0x00f032364295f56cb89ad03e1218f35f3f8d1d29ef14f9c457edca6b3555c60f",
		"0x27b9c329d9f56b94c3a1d8dc84f2b8e2e0feb636fbc5f6df1474c601e8b979be",
		"0x0908dce80a5004fe99b125b161d4b3ad596b71744eff190c1cec2aa116a90dd3",
		"0x022e071cf4eed456dc7f3a36b7b190c6a1f991ef8c5809f612cb193e9c28af78",
		"0x08caaaeb4b4b5f589c338c00a7908a5ebae73ff50f3f1a8911f424a476ec7a50",
		"0x0d9e5d2c43d671f2f986e9456613ce46fce4bf410950788b8e7584b9eb8f489e",
		"0x15f19af55d5d29b82570ec8a8cdb79286719e2d11de811da71d6871874365f93",
		"0x14d4892218a45bef768d6e148825e647729c4f273a4ec038715c33581e2361e8",
		"0x10e589ae3afb5613bd405d5d0c04c129ab6617e13dad7a2d59e2278dc55aa377",
		"0x201c77fa8749ec28af53e24913e5bde201e6a7816c0b6e229b9191724ce46a45",
		"0x1cb29bedc1cac19bcacb59ab2db20b0378e99cb21bec9f3483af1d402aeb5299",
		"0x19f91688756802bd7f9fa4ca5de2089bb77aa1621c68103800365826945b15b3",
		"0x25206c2f6e39dd366f6dfffa8fd80d8e3650bb097797e84b3d13a616f0074243",
		"0x28815c9a1c9d638886d6ac193df55f98824c491d09bbbd712f96b5adfeba742e",
		"0x28c6e0e2959d4519185a50e1fc8f37e9ca73be1ce73a620a8f74f13289f76340",
		"0x2a9951c1901f40491757ba70f024d203361a68083b4d988a3eb876b91f2a9836",
	}

	treap := buildTreap()
	list := treapToList(treap)
	for i, node := range list {
		assert.Equal(t, shouldBeBuilt[i][2:], hex.EncodeToString(node.Hash), "actual node: ", node)
	}
}

func TestTreap_Remove(t *testing.T) {
	shouldBeRemoved := map[string]struct{}{
		"0x15f19af55d5d29b82570ec8a8cdb79286719e2d11de811da71d6871874365f93": {},
		"0x28815c9a1c9d638886d6ac193df55f98824c491d09bbbd712f96b5adfeba742e": {},
		"0x201c77fa8749ec28af53e24913e5bde201e6a7816c0b6e229b9191724ce46a45": {},
		"0x27b9c329d9f56b94c3a1d8dc84f2b8e2e0feb636fbc5f6df1474c601e8b979be": {},
		"0x022e071cf4eed456dc7f3a36b7b190c6a1f991ef8c5809f612cb193e9c28af78": {},
		"0x14d4892218a45bef768d6e148825e647729c4f273a4ec038715c33581e2361e8": {},
	}

	shouldRemain := make([]string, 0, len(leavesToInsert)-len(shouldBeRemoved))
	for _, toIns := range leavesToInsert {
		if _, ok := shouldBeRemoved[toIns]; !ok {
			shouldRemain = append(shouldRemain, toIns)
		}
	}

	treap := buildTreap()
	for toRm := range shouldBeRemoved {
		bytes, _ := hex.DecodeString(toRm[2:])
		treap.Remove(bytes) // now breaks on recursion
	}
	// how will orphan nodes work in this case?
	list := treapToList(treap)
	for _, node := range list {
		assert.Contains(t, shouldRemain, hex.EncodeToString(node.Hash), "absent node: ", node)
	}
	for _, node := range list {
		assert.NotContains(t, shouldBeRemoved, hex.EncodeToString(node.Hash), "present node: ", node)
	}
}

func buildTreap() *Treap {
	treap := new(Treap)
	for _, leaf := range leavesToInsert {
		bytes, _ := hex.DecodeString(leaf[2:])
		treap.Insert(bytes, derivePriority(bytes))
	}

	return treap
}

func treapToList(treap *Treap) []Node {
	list := make([]Node, 0, 16)

	var traverse func(node *Node)
	traverse = func(node *Node) {
		if node == nil {
			return
		}
		list = append(list, *node)
		traverse(node.Left)
		traverse(node.Right)
	}

	traverse(treap.Root)
	return list
}
