package bn254

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestPointG1_HashToPoint(t *testing.T) {
	// reference test 1
	p := new(pointG1).Hash([]byte("abc"))
	pBuf, err := p.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	refBuf, err := hex.DecodeString("1d9f1708091409260f8435f1a5477e0a29507c51d1f2d5a9b0246978c8b06efe04fc97f7d6ed51fdf2920eea84eb1be09aa77322c1111593cde486d72188402f")
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
	refBuf2, err := hex.DecodeString("27f3f48152dff5c587f23f29b86cb300699b1bd5aba9629d8d8780d5b07b60c11b34cf4d571612c7d3ede8a359251abdfa1aaa390056cd06c0c8e6a786e5fe81")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(p2Buf, refBuf2) {
		t.Error("hash does not match reference")
	}
}

func TestExpandMsg(t *testing.T) {
	_msg, err := hex.DecodeString("cd91b51a7278becadf9b0c673dad805a0e36dfaf9bc86bc0a22303c69c0133b4")
	if err != nil {
		t.Error("decode errored", err.Error())
	}

	expanded, err := expandMsgXmd(
		[]byte("BLS_SIG_BN254G1_XMD:KECCAK-256_S"), // NB: trimmed down to 32B
		_msg,
		96,
	)
	if err != nil {
		t.Error("expandMsg errored", err.Error())
	}

	if hex.EncodeToString(expanded) != "fdb291d400e5067af2451380c64d973c2064e443427645680ef6826a3c8dde0d51be4a4fbf68db785869e9671525dbbcb17b349e6def2afe8ae92848f625b539c49bde740c170b03ee5ec8801401d69342c175b60746b4df740ba61b71f10688" {
		t.Error("expandMsg does not match ref")
	}
}

func TestHashToField(t *testing.T) {
	_msg, err := hex.DecodeString("b6cd92b293a7e066f947d55a3d3f6ff1d12491b9418a75eb7eda9e0452f8a802")
	if err != nil {
		t.Error("decode errored", err.Error())
	}

	x, y := hashToField(
		[]byte("BLS_SIG_BN254G1_XMD:KECCAK-256_S"), // NB: trimmed down to 32B
		_msg,
	)

	xRef, success := new(big.Int).SetString("21388573764901551231292644833553850174866019666418231876069068938683826780505", 10)
	if !success {
		t.Error("bigint encode errored")
	}
	yRef, success := new(big.Int).SetString("19256864419500893614579951126008683517059415729946874015264273858774622719340", 10)
	if !success {
		t.Error("bigint encode errored")
	}

	if x.Cmp(xRef) != 0 {
		t.Error("hashToField x does not match ref", x, xRef)
	}
	if y.Cmp(yRef) != 0 {
		t.Error("hashToField y does not match ref", y, yRef)
	}
}
