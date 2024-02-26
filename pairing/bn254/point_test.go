package bn254

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPointG1_HashToPoint(t *testing.T) {
	domain := []byte("domain_separation_tag_test_12345")

	// reference test 1
	p := newPointG1(domain).Hash([]byte("abc"))
	pBuf, err := p.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf, err := hex.DecodeString("1162012021d4e0f95f3d1581abb47965f00fbe4d687c2862d96c6bcd1d1b8c2802edb2671f058e94c55bf159f3b77c66861f48e92eadaaf490bd40298bc7250d")
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
	refBuf2, err := hex.DecodeString("0663a666beede006480859f65d7057e783e0d7b3bc31ac05350c97358a92170909963f538b0c0d8d55fcd77bb1cf718837cb1cc69c41a2a7531fc278ac8d2cc4")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(p2Buf, refBuf2) {
		t.Error("hash does not match reference")
	}
}

func TestExpandMsg(t *testing.T) {
	_msg, err := hex.DecodeString("361d32c5249fd47d7e59572679947e2dc5d22bd9583e0c1a6b2cefe3b268693a")
	if err != nil {
		t.Error("decode errored", err.Error())
	}

	expanded := expandMsgXmd(
		[]byte("BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_"),
		_msg,
		96,
	)
	if err != nil {
		t.Error("expandMsg errored", err.Error())
	}

	if hex.EncodeToString(expanded) != "2a0948190aa9108b487183707b61cebfa3d36e8828908be74d5fa31249a43682fa17310294d698d107ef7075f4e9851b2328c3adc7f4f7ff436fa4d49b55f4d0c22dd5712c17ccc802960d7ee735af4d112b88b8431cdd54bc2632fbf528d077" {
		t.Error("expandMsg does not match ref", hex.EncodeToString(expanded))
	}
}

func TestHashToField(t *testing.T) {
	_msg, err := hex.DecodeString("19c2146fe74be3bec967fc4bea0bd1c95b414631d505c54c06d194c2141f5073")
	if err != nil {
		t.Error("decode errored", err.Error())
	}

	x, y := hashToField(
		[]byte("BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_"),
		_msg,
	)

	if x.String() != "0edb1e4dd8b720eb2752ee0df3289a82c00567d6f862f4212e700c85b8e28087" {
		t.Error("hashToField x does not match ref", x)
	}
	if y.String() != "2cfcfdb53a812bac1c030b4074ca56ec6fc478689cdbc5c657e7b332f50e02bc" {
		t.Error("hashToField y does not match ref", y)
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

// func TestHashToPoint(t *testing.T) {
// 	dst := []byte("BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_")
// 	_msg, err := hex.DecodeString("d3420d154786d7dc15997457c4598fa14f9345bb5157b14bb8bfbad3816cbf84")
// 	if err != nil {
// 		t.Error("decode errored", err.Error())
// 	}
// 	p := hashToPoint(dst, _msg).(*pointG1)
// 	p.g.MakeAffine()
// 	x, y := &gfP{}, &gfP{}
// 	montDecode(x, &p.g.x)
// 	montDecode(y, &p.g.y)

// 	// Reference values are taken from:
// 	// https://github.com/kevincharm/bls-bn254/blob/bef9dad5d99b3c99a17fd85e3328daea5824dac9/scripts/hash.ts
// 	// Clone the repo, run `yarn` to install deps, then run:
// 	// yarn bls:hash 0xd3420d154786d7dc15997457c4598fa14f9345bb5157b14bb8bfbad3816cbf84
// 	if x.String() != "298a790a58f3f0595879f168f410acd0c78537f5879ad087a24f3d3797f10d31" {
// 		t.Error("hashToPoint x does not match ref")
// 	}
// 	if y.String() != "06b050da817646da43652026853a749b7b43358be273d9037505dfc17fb51090" {
// 		t.Error("hashToPoint y does not match ref")
// 	}
// }
