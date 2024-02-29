package bn254

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPointG1_HashToPoint(t *testing.T) {
	domain := []byte("domain_separation_tag_test_12345")

	// reference test 1
	p := newPointG1(domain).Hash([]byte("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"))
	pBuf, err := p.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf, err := hex.DecodeString("13af4ace8febc1ec800f7d33d66868310516bce9cb1b7f7c68607f9ba6dba92c1823b8f13feeb8dad6b152eb2bbefbe59452f9519c88230b55d0b699498db6f1")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(pBuf, refBuf) {
		t.Error("hash does not match reference")
	}

	// reference test 2
	buf2, err := hex.DecodeString("e0a05cbb37fd6c159732a8c57b981773f7480695328b674d8a9cc083377f1811")
	if err != nil {
		t.Error(err)
	}
	p2 := newPointG1(domain).Hash(buf2)
	p2Buf, err := p2.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf2, err := hex.DecodeString("07abd743dc93dfa3a8ee4ab449b1657dc6232c589612b23a54ea461c7232101e2533badbee56e8457731fc35bb7630236623e4614e4f8acb4a0c3282df58a289")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(p2Buf, refBuf2) {
		t.Error("hash does not match reference")
	}
}

func TestExpandMsg(t *testing.T) {
	_msg, err := hex.DecodeString("af6c1f30b2f3f2fd448193f90d6fb55b544a")
	if err != nil {
		t.Error("decode errored", err.Error())
	}

	expanded := expandMsgXmdKeccak256(
		[]byte("BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_"),
		_msg,
		96,
	)
	if err != nil {
		t.Error("expandMsg errored", err.Error())
	}

	if hex.EncodeToString(expanded) != "bd365d9672926bbb6887f8c0ce88d1edc0c20bd46f6af54e80c7edc15ac1c5eba9e754994af715195aa8acb3f21febae2b9626bc1b06c185922455908d1c8db3d370fe339995718e344af3add0aa77d3bd48d0d9f3ebe26b88cbb393325c1c6e" {
		t.Error("expandMsg does not match ref", hex.EncodeToString(expanded))
	}
}

func TestHashToField(t *testing.T) {
	dst := []byte("BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_")
	for i, testVector := range hashToFieldTestVectors {
		_msg, err := hex.DecodeString(testVector.Msg)
		if err != nil {
			t.Error("decode errored", err.Error())
		}

		x, y := hashToField(
			dst,
			_msg,
		)

		if x.String() != testVector.RefX {
			t.Errorf("[%d] hashToField x does not match ref %s != %s", i, x, testVector.RefX)
		}
		if y.String() != testVector.RefY {
			t.Errorf("[%d] hashToField y does not match ref %s != %s", i, y, testVector.RefY)
		}
	}
}

func TestMapToPoint(t *testing.T) {
	dst := []byte("BN254G1_XMD:KECCAK-256_SVDW_RO_NUL_")

	for i, testVector := range mapToPointTestVectors {
		u := newGFpFromBase10(testVector.U)
		pRef := newPointG1(dst).Base().(*pointG1)
		pRef.g.x.Set(newGFpFromBase10(testVector.RefX))
		pRef.g.y.Set(newGFpFromBase10(testVector.RefY))

		p := mapToPoint(dst, u).(*pointG1)

		if !p.Equal(pRef) {
			t.Errorf("[%d] point does not match ref (%s != %s)", i, p.String(), pRef.String())
		}
	}
}

func TestHashToPoint(t *testing.T) {
	dst := []byte("BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_")
	_msg, err := hex.DecodeString("d3420d154786d7dc15997457c4598fa14f9345bb5157b14bb8bfbad3816cbf84")
	if err != nil {
		t.Error("decode errored", err.Error())
	}
	p := hashToPoint(dst, _msg).(*pointG1)
	p.g.MakeAffine()
	x, y := &gfP{}, &gfP{}
	montDecode(x, &p.g.x)
	montDecode(y, &p.g.y)

	// Reference values are taken from:
	// https://github.com/kevincharm/bls-bn254/blob/bef9dad5d99b3c99a17fd85e3328daea5824dac9/scripts/hash.ts
	// Clone the repo, run `yarn` to install deps, then run:
	// yarn bls:hash 0xd3420d154786d7dc15997457c4598fa14f9345bb5157b14bb8bfbad3816cbf84
	if x.String() != "298a790a58f3f0595879f168f410acd0c78537f5879ad087a24f3d3797f10d31" {
		t.Error("hashToPoint x does not match ref")
	}
	if y.String() != "06b050da817646da43652026853a749b7b43358be273d9037505dfc17fb51090" {
		t.Error("hashToPoint y does not match ref")
	}
}
