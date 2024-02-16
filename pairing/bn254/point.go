package bn254

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
	"golang.org/x/crypto/sha3"
)

var marshalPointID1 = [8]byte{'b', 'n', '2', '5', '4', '.', 'g', '1'}
var marshalPointID2 = [8]byte{'b', 'n', '2', '5', '4', '.', 'g', '2'}
var marshalPointIDT = [8]byte{'b', 'n', '2', '5', '4', '.', 'g', 't'}

type pointG1 struct {
	g   *curvePoint
	dst []byte
}

func newPointG1(dst []byte) *pointG1 {
	p := &pointG1{g: &curvePoint{}, dst: dst}
	return p
}

func (p *pointG1) fromBigInt(x, y *big.Int) *pointG1 {
	gx, gy := new(gfP), new(gfP)
	gx.Unmarshal(zeroPadBytes(x.Bytes(), 32))
	gy.Unmarshal(zeroPadBytes(y.Bytes(), 32))
	montEncode(gx, gx)
	montEncode(gy, gy)

	p.g.Set(&curvePoint{*gx, *gy, *newGFp(1), *newGFp(1)})
	return p
}

func (p *pointG1) Equal(q kyber.Point) bool {
	x, _ := p.MarshalBinary()
	y, _ := q.MarshalBinary()
	return subtle.ConstantTimeCompare(x, y) == 1
}

func (p *pointG1) Null() kyber.Point {
	p.g.SetInfinity()
	return p
}

func (p *pointG1) Base() kyber.Point {
	p.g.Set(curveGen)
	return p
}

func (p *pointG1) Pick(rand cipher.Stream) kyber.Point {
	s := mod.NewInt64(0, Order).Pick(rand)
	p.Base()
	p.g.Mul(p.g, &s.(*mod.Int).V)
	return p
}

func (p *pointG1) Set(q kyber.Point) kyber.Point {
	x := q.(*pointG1).g
	p.g.Set(x)
	return p
}

// Clone makes a hard copy of the point
func (p *pointG1) Clone() kyber.Point {
	q := newPointG1(p.dst)
	q.g = p.g.Clone()
	return q
}

func (p *pointG1) EmbedLen() int {
	panic("bn254.G1: unsupported operation")
}

func (p *pointG1) Embed(data []byte, rand cipher.Stream) kyber.Point {
	// XXX: An approach to implement this is:
	// - Encode data as the x-coordinate of a point on y²=x³+3 where len(data)
	//   is stored in the least significant byte of x and the rest is being
	//   filled with random values, i.e., x = rand || data || len(data).
	// - Use the Tonelli-Shanks algorithm to compute the y-coordinate.
	// - Convert the new point to Jacobian coordinates and set it as p.
	panic("bn254.G1: unsupported operation")
}

func (p *pointG1) Data() ([]byte, error) {
	panic("bn254.G1: unsupported operation")
}

func (p *pointG1) Add(a, b kyber.Point) kyber.Point {
	x := a.(*pointG1).g
	y := b.(*pointG1).g
	p.g.Add(x, y) // p = a + b
	return p
}

func (p *pointG1) Sub(a, b kyber.Point) kyber.Point {
	q := newPointG1(p.dst)
	return p.Add(a, q.Neg(b))
}

func (p *pointG1) Neg(q kyber.Point) kyber.Point {
	x := q.(*pointG1).g
	p.g.Neg(x)
	return p
}

func (p *pointG1) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointG1(p.dst).Base()
	}
	t := s.(*mod.Int).V
	r := q.(*pointG1).g
	p.g.Mul(r, &t)
	return p
}

func (p *pointG1) MarshalBinary() ([]byte, error) {
	// Clone is required as we change the point
	p = p.Clone().(*pointG1)

	n := p.ElementSize()
	// Take a copy so that p is not written to, so calls to MarshalBinary
	// are threadsafe.
	pgtemp := *p.g
	pgtemp.MakeAffine()
	ret := make([]byte, p.MarshalSize())
	if pgtemp.IsInfinity() {
		return ret, nil
	}
	tmp := &gfP{}
	montDecode(tmp, &pgtemp.x)
	tmp.Marshal(ret)
	montDecode(tmp, &pgtemp.y)
	tmp.Marshal(ret[n:])
	return ret, nil
}

func (p *pointG1) MarshalID() [8]byte {
	return marshalPointID1
}

func (p *pointG1) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *pointG1) UnmarshalBinary(buf []byte) error {
	n := p.ElementSize()
	if len(buf) < p.MarshalSize() {
		return errors.New("bn254.G1: not enough data")
	}
	if p.g == nil {
		p.g = &curvePoint{}
	} else {
		p.g.x, p.g.y = gfP{0}, gfP{0}
	}

	p.g.x.Unmarshal(buf)
	p.g.y.Unmarshal(buf[n:])
	montEncode(&p.g.x, &p.g.x)
	montEncode(&p.g.y, &p.g.y)

	zero := gfP{0}
	if p.g.x == zero && p.g.y == zero {
		// This is the point at infinity
		p.g.y = *newGFp(1)
		p.g.z = gfP{0}
		p.g.t = gfP{0}
	} else {
		p.g.z = *newGFp(1)
		p.g.t = *newGFp(1)
	}

	if !p.g.IsOnCurve() {
		return errors.New("bn254.G1: malformed point")
	}

	return nil
}

func (p *pointG1) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *pointG1) MarshalSize() int {
	return 2 * p.ElementSize()
}

func (p *pointG1) ElementSize() int {
	return 256 / 8
}

func (p *pointG1) String() string {
	return "bn254.G1" + p.g.String()
}

func (p *pointG1) Hash(m []byte) kyber.Point {
	return hashToPoint(p.dst, m)
}

func hashToPoint(domain, m []byte) kyber.Point {
	e0, e1 := hashToField(domain, m)
	p0 := newPointG1(domain).fromBigInt(mapToPoint(e0))
	p1 := newPointG1(domain).fromBigInt(mapToPoint(e1))
	p := p0.Add(p0, p1)
	return p
}

func hashToField(domain, m []byte) (*big.Int, *big.Int) {
	const u = 48
	_msg := expandMsgXmd(domain, m, 2*u)
	x := new(big.Int)
	y := new(big.Int)
	x.SetBytes(_msg[0:48]).Mod(x, p)
	y.SetBytes(_msg[48:96]).Mod(y, p)
	return x, y
}

// `mapToPoint` implements a specialised SW mapping for BN curves from the paper
//
//	 Fouque, P.-A. and M. Tibouchi, "Indifferentiable Hashing to Barreto--Naehrig Curves",
//		In Progress in Cryptology -
//		LATINCRYPT 2012, pages 1-17,
//		DOI 10.1007/978-3-642-33481-8_1, 2012,
//		<https://doi.org/10.1007/978-3-642-33481-8_1>.
//
// Ref implementations:
//
//	https://github.com/herumi/mcl/blob/5f4449efd08388009f9abce06c44fc26730193e7/include/mcl/bn.hpp#L343
//	https://github.com/thehubbleproject/hubble-contracts/blob/f1c13fe4e1a0dc9ab1f150895de7c0e654ee46b0/contracts/libs/BLS.sol#L139
func mapToPoint(x *big.Int) (*big.Int, *big.Int) {
	if x.Cmp(p) >= 0 {
		panic("mapToPointFT: invalid field element")
	}

	_, decision := modsqrt(x)

	a0 := mulmodp(x, x)
	a0 = addmodp(a0, new(big.Int).SetUint64(4))
	a1 := mulmodp(x, z0)
	a2 := mulmodp(a1, a0)
	a2 = a2.ModInverse(a2, p)
	a1 = mulmodp(a1, a1)
	a1 = mulmodp(a1, a2)

	// x1
	a1 = mulmodp(x, a1)
	x = addmodp(z1, new(big.Int).Sub(p, a1))
	// check curve
	a1 = mulmodp(x, x)
	a1 = mulmodp(a1, x)
	a1 = addmodp(a1, new(big.Int).SetUint64(3))
	a1, found := modsqrt(a1)
	if found {
		if !decision {
			a1 = new(big.Int).Sub(p, a1)
		}
		return x, a1
	}

	// x2
	x = new(big.Int).Sub(p, addmodp(x, new(big.Int).SetUint64(1)))
	// check curve
	a1 = mulmodp(x, x)
	a1 = mulmodp(a1, x)
	a1 = addmodp(a1, new(big.Int).SetUint64(3))
	a1, found = modsqrt(a1)
	if found {
		if !decision {
			a1 = new(big.Int).Sub(p, a1)
		}
		return x, a1
	}

	// x3
	x = mulmodp(a0, a0)
	x = mulmodp(x, x)
	x = mulmodp(x, a2)
	x = mulmodp(x, a2)
	x = addmodp(x, new(big.Int).SetUint64(1))
	// must be on curve
	a1 = mulmodp(x, x)
	a1 = mulmodp(a1, x)
	a1 = addmodp(a1, new(big.Int).SetUint64(3))
	a1, found = modsqrt(a1)
	if !found {
		panic("BLS: bad ft mapping implementation")
	}
	if !decision {
		a1 = new(big.Int).Sub(p, a1)
	}
	return x, a1
}

// `expandMsgXmd` implements expand_message_xmd from IETF RFC9380 Sec 5.3.1
// where H is keccak256
func expandMsgXmd(domain, msg []byte, outlen int) []byte {
	if len(domain) > 255 {
		panic(fmt.Sprintf("invalid DST length: %d", len(domain)))
	}
	b_in_bytes := 32
	r_in_bytes := b_in_bytes * 2
	ell := (outlen + b_in_bytes - 1) / b_in_bytes
	if ell > 255 {
		panic(fmt.Sprintf("invalid xmd length: %d", ell))
	}
	// DST_prime <- domain<len(domain)>|len(domain)<1>
	DST_prime := bytes.NewBuffer(make([]byte, 0, len(domain)+1))
	DST_prime.Write(domain)
	DST_prime.WriteByte(byte(len(domain)))
	// msg_prime <- Z_pad<r_in_bytes>|msg<var>|l_i_b_str<2>|0<1>|DST_prime<var>
	msg_prime_input := bytes.NewBuffer(make([]byte, r_in_bytes, r_in_bytes+len(msg)+2+1+DST_prime.Len()))
	// write msg to offset at r_in_bytes
	msg_prime_input.Write(msg)
	msg_prime_input.WriteByte(byte((outlen >> 8) & 0xff)) // l_i_b_str
	msg_prime_input.WriteByte(byte(outlen & 0xff))        // l_i_b_str
	msg_prime_input.WriteByte(0)
	msg_prime_input.Write(DST_prime.Bytes())
	msg_prime := new(big.Int).SetBytes(keccak256(msg_prime_input.Bytes()))

	b := make([]*big.Int, ell)

	b0_input := bytes.NewBuffer(make([]byte, 0, 32+1+DST_prime.Len()))
	b0_input.Write(msg_prime.Bytes())
	b0_input.WriteByte(1)
	b0_input.Write(DST_prime.Bytes())
	b[0] = new(big.Int).SetBytes(keccak256(b0_input.Bytes()))
	for i := 1; i < ell; i++ {
		bi_input := bytes.NewBuffer(make([]byte, 0, 32+1+DST_prime.Len()))
		bi_input.Write(zeroPadBytes(new(big.Int).Set(msg_prime).Xor(msg_prime, b[i-1]).Bytes(), 32))
		bi_input.WriteByte(byte(i + 1))
		bi_input.Write(DST_prime.Bytes())
		b[i] = new(big.Int).SetBytes(keccak256(bi_input.Bytes()))
	}

	pseudo_random_bytes := bytes.NewBuffer(make([]byte, 0, outlen))
	for i := 0; i < outlen/32; i++ {
		pseudo_random_bytes.Write(zeroPadBytes(b[i].Bytes(), 32))
	}
	return pseudo_random_bytes.Bytes()
}

func addmodp(a, b *big.Int) *big.Int {
	result := new(big.Int).Add(a, b)
	result = result.Mod(result, p)
	return result
}

func mulmodp(a, b *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	result = result.Mod(result, p)
	return result
}

func modsqrt(x *big.Int) (*big.Int, bool) {
	result := new(big.Int).ModSqrt(x, p)
	return result, result != nil
}

func zeroPadBytes(m []byte, outlen int) []byte {
	if len(m) < outlen {
		padlen := outlen - len(m)
		out := bytes.NewBuffer(make([]byte, padlen, outlen))
		out.Write(m)
		return out.Bytes()
	}
	return m
}

func keccak256(m []byte) []byte {
	keccak := sha3.NewLegacyKeccak256()
	keccak.Write(m)
	h := keccak.Sum(nil)
	return h
}

type pointG2 struct {
	g   *twistPoint
	dst []byte
}

func newPointG2(dst []byte) *pointG2 {
	p := &pointG2{g: &twistPoint{}, dst: dst}
	return p
}

func (p *pointG2) Equal(q kyber.Point) bool {
	x, _ := p.MarshalBinary()
	y, _ := q.MarshalBinary()
	return subtle.ConstantTimeCompare(x, y) == 1
}

func (p *pointG2) Null() kyber.Point {
	p.g.SetInfinity()
	return p
}

func (p *pointG2) Base() kyber.Point {
	p.g.Set(twistGen)
	return p
}

func (p *pointG2) Pick(rand cipher.Stream) kyber.Point {
	s := mod.NewInt64(0, Order).Pick(rand)
	p.Base()
	p.g.Mul(p.g, &s.(*mod.Int).V)
	return p
}

func (p *pointG2) Set(q kyber.Point) kyber.Point {
	x := q.(*pointG2).g
	p.g.Set(x)
	return p
}

// Clone makes a hard copy of the field
func (p *pointG2) Clone() kyber.Point {
	q := newPointG2(p.dst)
	q.g = p.g.Clone()
	return q
}

func (p *pointG2) EmbedLen() int {
	panic("bn254.G2: unsupported operation")
}

func (p *pointG2) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bn254.G2: unsupported operation")
}

func (p *pointG2) Data() ([]byte, error) {
	panic("bn254.G2: unsupported operation")
}

func (p *pointG2) Add(a, b kyber.Point) kyber.Point {
	x := a.(*pointG2).g
	y := b.(*pointG2).g
	p.g.Add(x, y) // p = a + b
	return p
}

func (p *pointG2) Sub(a, b kyber.Point) kyber.Point {
	q := newPointG2(p.dst)
	return p.Add(a, q.Neg(b))
}

func (p *pointG2) Neg(q kyber.Point) kyber.Point {
	x := q.(*pointG2).g
	p.g.Neg(x)
	return p
}

func (p *pointG2) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointG2(p.dst).Base()
	}
	t := s.(*mod.Int).V
	r := q.(*pointG2).g
	p.g.Mul(r, &t)
	return p
}

func (p *pointG2) MarshalBinary() ([]byte, error) {
	// Clone is required as we change the point during the operation
	p = p.Clone().(*pointG2)

	n := p.ElementSize()
	if p.g == nil {
		p.g = &twistPoint{}
	}

	p.g.MakeAffine()

	ret := make([]byte, p.MarshalSize())
	if p.g.IsInfinity() {
		return ret, nil
	}

	temp := &gfP{}
	montDecode(temp, &p.g.x.x)
	temp.Marshal(ret[0*n:])
	montDecode(temp, &p.g.x.y)
	temp.Marshal(ret[1*n:])
	montDecode(temp, &p.g.y.x)
	temp.Marshal(ret[2*n:])
	montDecode(temp, &p.g.y.y)
	temp.Marshal(ret[3*n:])

	return ret, nil
}

func (p *pointG2) MarshalID() [8]byte {
	return marshalPointID2
}

func (p *pointG2) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *pointG2) UnmarshalBinary(buf []byte) error {
	n := p.ElementSize()
	if p.g == nil {
		p.g = &twistPoint{}
	}

	if len(buf) < p.MarshalSize() {
		return errors.New("bn254.G2: not enough data")
	}

	p.g.x.x.Unmarshal(buf[0*n:])
	p.g.x.y.Unmarshal(buf[1*n:])
	p.g.y.x.Unmarshal(buf[2*n:])
	p.g.y.y.Unmarshal(buf[3*n:])
	montEncode(&p.g.x.x, &p.g.x.x)
	montEncode(&p.g.x.y, &p.g.x.y)
	montEncode(&p.g.y.x, &p.g.y.x)
	montEncode(&p.g.y.y, &p.g.y.y)

	if p.g.x.IsZero() && p.g.y.IsZero() {
		// This is the point at infinity.
		p.g.y.SetOne()
		p.g.z.SetZero()
		p.g.t.SetZero()
	} else {
		p.g.z.SetOne()
		p.g.t.SetOne()

		if !p.g.IsOnCurve() {
			return errors.New("bn254.G2: malformed point")
		}
	}
	return nil
}

func (p *pointG2) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *pointG2) MarshalSize() int {
	return 4 * p.ElementSize()
}

func (p *pointG2) ElementSize() int {
	return 256 / 8
}

func (p *pointG2) String() string {
	return "bn254.G2" + p.g.String()
}

type pointGT struct {
	g *gfP12
}

func newPointGT() *pointGT {
	p := &pointGT{g: &gfP12{}}
	return p
}

func (p *pointGT) Equal(q kyber.Point) bool {
	x, _ := p.MarshalBinary()
	y, _ := q.MarshalBinary()
	return subtle.ConstantTimeCompare(x, y) == 1
}

func (p *pointGT) Null() kyber.Point {
	// TODO: This can be a precomputed constant
	p.Pair(newPointG1([]byte{}).Null(), newPointG2([]byte{}).Null())
	return p
}

func (p *pointGT) Base() kyber.Point {
	// TODO: This can be a precomputed constant
	p.Pair(newPointG1([]byte{}).Base(), newPointG2([]byte{}).Base())
	return p
}

func (p *pointGT) Pick(rand cipher.Stream) kyber.Point {
	s := mod.NewInt64(0, Order).Pick(rand)
	p.Base()
	p.g.Exp(p.g, &s.(*mod.Int).V)
	return p
}

func (p *pointGT) Set(q kyber.Point) kyber.Point {
	x := q.(*pointGT).g
	p.g.Set(x)
	return p
}

// Clone makes a hard copy of the point
func (p *pointGT) Clone() kyber.Point {
	q := newPointGT()
	q.g = p.g.Clone()
	return q
}

func (p *pointGT) EmbedLen() int {
	panic("bn254.GT: unsupported operation")
}

func (p *pointGT) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bn254.GT: unsupported operation")
}

func (p *pointGT) Data() ([]byte, error) {
	panic("bn254.GT: unsupported operation")
}

func (p *pointGT) Add(a, b kyber.Point) kyber.Point {
	x := a.(*pointGT).g
	y := b.(*pointGT).g
	p.g.Mul(x, y)
	return p
}

func (p *pointGT) Sub(a, b kyber.Point) kyber.Point {
	q := newPointGT()
	return p.Add(a, q.Neg(b))
}

func (p *pointGT) Neg(q kyber.Point) kyber.Point {
	x := q.(*pointGT).g
	p.g.Conjugate(x)
	return p
}

func (p *pointGT) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointGT().Base()
	}
	t := s.(*mod.Int).V
	r := q.(*pointGT).g
	p.g.Exp(r, &t)
	return p
}

func (p *pointGT) MarshalBinary() ([]byte, error) {
	n := p.ElementSize()
	ret := make([]byte, p.MarshalSize())
	temp := &gfP{}

	montDecode(temp, &p.g.x.x.x)
	temp.Marshal(ret[0*n:])
	montDecode(temp, &p.g.x.x.y)
	temp.Marshal(ret[1*n:])
	montDecode(temp, &p.g.x.y.x)
	temp.Marshal(ret[2*n:])
	montDecode(temp, &p.g.x.y.y)
	temp.Marshal(ret[3*n:])
	montDecode(temp, &p.g.x.z.x)
	temp.Marshal(ret[4*n:])
	montDecode(temp, &p.g.x.z.y)
	temp.Marshal(ret[5*n:])
	montDecode(temp, &p.g.y.x.x)
	temp.Marshal(ret[6*n:])
	montDecode(temp, &p.g.y.x.y)
	temp.Marshal(ret[7*n:])
	montDecode(temp, &p.g.y.y.x)
	temp.Marshal(ret[8*n:])
	montDecode(temp, &p.g.y.y.y)
	temp.Marshal(ret[9*n:])
	montDecode(temp, &p.g.y.z.x)
	temp.Marshal(ret[10*n:])
	montDecode(temp, &p.g.y.z.y)
	temp.Marshal(ret[11*n:])

	return ret, nil
}

func (p *pointGT) MarshalID() [8]byte {
	return marshalPointIDT
}

func (p *pointGT) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *pointGT) UnmarshalBinary(buf []byte) error {
	n := p.ElementSize()
	if len(buf) < p.MarshalSize() {
		return errors.New("bn254.GT: not enough data")
	}

	if p.g == nil {
		p.g = &gfP12{}
	}

	p.g.x.x.x.Unmarshal(buf[0*n:])
	p.g.x.x.y.Unmarshal(buf[1*n:])
	p.g.x.y.x.Unmarshal(buf[2*n:])
	p.g.x.y.y.Unmarshal(buf[3*n:])
	p.g.x.z.x.Unmarshal(buf[4*n:])
	p.g.x.z.y.Unmarshal(buf[5*n:])
	p.g.y.x.x.Unmarshal(buf[6*n:])
	p.g.y.x.y.Unmarshal(buf[7*n:])
	p.g.y.y.x.Unmarshal(buf[8*n:])
	p.g.y.y.y.Unmarshal(buf[9*n:])
	p.g.y.z.x.Unmarshal(buf[10*n:])
	p.g.y.z.y.Unmarshal(buf[11*n:])
	montEncode(&p.g.x.x.x, &p.g.x.x.x)
	montEncode(&p.g.x.x.y, &p.g.x.x.y)
	montEncode(&p.g.x.y.x, &p.g.x.y.x)
	montEncode(&p.g.x.y.y, &p.g.x.y.y)
	montEncode(&p.g.x.z.x, &p.g.x.z.x)
	montEncode(&p.g.x.z.y, &p.g.x.z.y)
	montEncode(&p.g.y.x.x, &p.g.y.x.x)
	montEncode(&p.g.y.x.y, &p.g.y.x.y)
	montEncode(&p.g.y.y.x, &p.g.y.y.x)
	montEncode(&p.g.y.y.y, &p.g.y.y.y)
	montEncode(&p.g.y.z.x, &p.g.y.z.x)
	montEncode(&p.g.y.z.y, &p.g.y.z.y)

	// TODO: check if point is on curve

	return nil
}

func (p *pointGT) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *pointGT) MarshalSize() int {
	return 12 * p.ElementSize()
}

func (p *pointGT) ElementSize() int {
	return 256 / 8
}

func (p *pointGT) String() string {
	return "bn254.GT" + p.g.String()
}

func (p *pointGT) Finalize() kyber.Point {
	buf := finalExponentiation(p.g)
	p.g.Set(buf)
	return p
}

func (p *pointGT) Miller(p1, p2 kyber.Point) kyber.Point {
	a := p1.(*pointG1).g
	b := p2.(*pointG2).g
	p.g.Set(miller(b, a))
	return p
}

func (p *pointGT) Pair(p1, p2 kyber.Point) kyber.Point {
	a := p1.(*pointG1).g
	b := p2.(*pointG2).g
	p.g.Set(optimalAte(b, a))
	return p
}
