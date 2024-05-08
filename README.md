# LDIF SDK
## Description

General toolkit to work with ICAO CSCA MasterLists. It may:
 * Read and parse into different data structures `.ldif` files (as an example [ICAO PKD](https://pkddownloadsg.icao.int/) was used)
 * Create dynamic Merkle tree with treap data structure
 * Hash underlying certificates public keys
 * Build Merkle tree from previous point that stores certificates' hashes and verifies inclusion of a certificate 

Moreover, this library is compatible with [gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile) (no C libraries and only compatible types). 
But to be able to surely compile it high-level [wrapper](./mt/main.go) should be used, binding scripts could be found 
in the [scripts](./scripts) directory.
 
## LDIF certificates parser

An LDIF file consists of a series of records separated by line separators.  A
record consists of a sequence of lines describing a directory entry,
or a sequence of lines describing a set of changes to a directory
entry. More info about LDIF format may be found in [RFC 2849](https://datatracker.ietf.org/doc/html/rfc2849).

Our library provides different approaches for parsing data: reading file from 
filesystem, reading data from `io.Reader` or from raw file bytes. Under the hood it looks through the file,
searching by desired phrases, then fetched parts (master lists) decoded and unmarshalled to the structure with 
underlying certificates list.

To start working with ICAO ldif parser these code snippets may be used:

```go
    converter, err := FromFile(pathToLdifFile) // Read file and parse it
    if err != nil {
        return errors.Wrap(err, "failed to create new ldif converter")	
    }
	
    ...

    converter, err := FromReader(reader) // Read data from io.Reader and parse it
    if err != nil {
        return errors.Wrap(err, "failed to create new ldif converter")
    }
	
    ...

    converter, err := NewLDIF(rawBytes) // Parse raw file bytes 
    if err != nil {
        return errors.Wrap(err, "failed to create new ldif converter")
    }
```

After reading and parsing LDIF data these certificates can be converted into different formats: 

* PEM - using `converter.ToPem()` will reproduce an array of strings that stores certificates in a [PEM](https://datatracker.ietf.org/doc/html/rfc7468) format
* X509 - using `converter.ToX509()` witll return an array of certificates in a [x509](https://datatracker.ietf.org/doc/html/rfc5280) format 

In addition, there is a method `converter.RawPubKeys()` that gives an ability to get all public keys from parsed certificates, except duplicates and unsupported types (
nowadays it handles only RSA public keys).

More examples and usages can be found in [test file](./ldif/ldif_test.go). 


## Merkle Tree

### Treap Merkle Tree
Dynamic treap-based Merkle tree is used to store the CSCA public key hashes, see [treap](https://en.wikipedia.org/wiki/Treap).

To start working with tree `New()` should be called, the realisation implements basic interface to work with tree that looks like:

```go
    type ITreap interface {
        Remove(key []byte)
        Insert(key []byte, priority uint64)
        MerklePath(key []byte) ([][]byte, []int)
        MerkleRoot() []byte
    }
```

Worth to notice, if the tree has to be equal on different services with the same input keys, the priority should be
generated deterministically, otherwise the leaf order will be different. This package also provides some [tests](./mt/treap_tree_test.go)
that can be used as an example.

## Cert Tree

Furthermore, there is an interface that builds Treap Merkle Tree from certificates list. This wrapper was created
in accordance with the requirements for mobile developers, so the function arguments and responses consist of simple
types. 

As was mentioned before, the priority for our keys are generated deterministically using such formula: 
`priority = hash(key) mod MAX_UINT64`.

This package provides several options to build certificates tree from:
* encoded x509 certificates list - `BuildTree(encodedList)` - this function will decode the argument, retrieve public
keys from the certificates and build a new tree;
* raw leaves (public keys) - `BuildFromRaw(leaves)` - this function will hash raw keys and then build tree;
* Cosmos network - `BuildFromCosmos(grpcAddr, isSecure)` - this function will establish gRPC connection for given
address and fetch tree that is stored in Cosmos network using `/rarimo/rarimo-core/cscalist/tree` query. Then it
will build tree with given key hashes.

Previous functions returns new instance of a certificate tree that has several useful method to work with created data 
structure:
* `Root()` - get current tree root
* `IsExists()` - check if the underlying treap tree is initialised (or whether the root is empty) 
* `GenerateInclusionProof(pemCertificate)` - generates inclusion proof for given certificate. The proof is such structure:
```go
    type Proof struct {
        // Siblings is a list of non-empty sibling hashes to recover root.
        Siblings [][]byte `json:"siblings"`
    }
```
