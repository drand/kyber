package bn254

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPointG1_HashToPoint(t *testing.T) {
	// reference test 1
	p := new(pointG1).Hash([]byte("abc"))
	pBuf, err := p.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf, err := hex.DecodeString("294b2b66eb6cef6d18506fbad92a190ae97f21ef5cc21af4ffaf5b1d68891dd82b224bd4a48a537d3efd9570565c896fc795b3a8ee352d9abc453eb1b026097e")
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
	p2 := new(pointG1).Hash(buf2)
	p2Buf, err := p2.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf2, err := hex.DecodeString("1444853e16a3f959e9ff1da9c226958f9ee4067f82451bcf88ecc5980cf2c4d7165d8da4064488e275ea88416df6cb32fa86d5da8ca35a01d8db8b0676a649f2")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(p2Buf, refBuf2) {
		t.Error("hash does not match reference")
	}
}
