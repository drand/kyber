package ibe

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
)

type Ciphertext struct {
	// Random point rP
	U kyber.Point
	// Sigma attached to ID: sigma XOR H(rG_id)
	V []byte
	// ciphertext of the message M XOR H(sigma)
	W []byte
}

// H2Tag is the domain separation tag for the H2 hash function
func H2Tag() []byte {
	return []byte("IBE-H2")
}

// H3Tag is the domain separation tag for the H3 hash function
func H3Tag() []byte {
	return []byte("IBE-H3")
}

// H4Tag is the domain separation tag for the H4 hash function
func H4Tag() []byte {
	return []byte("IBE-H4")
}

// Encrypt implements the cca identity based encryption scheme from
// https://crypto.stanford.edu/~dabo/pubs/papers/bfibe.pdf for more information
// about the scheme.
// - master is the master key on G1
// - ID is the ID towards which we encrypt the message
// - msg is the actual message
// - seed is the random seed to generate the random element (sigma) of the encryption
// The suite must produce points which implements the `HashablePoint` interface.
func Encrypt(s pairing.Suite, master kyber.Point, ID, msg []byte) (*Ciphertext, error) {
	if len(msg)>>16 > 0 {
		// we're using blake2 as XOF which only outputs 2^16-1 length
		return nil, errors.New("plaintext too long for blake2")
	}
	// 1. Compute Gid = e(master,Q_id)
	hG2, ok := s.G2().Point().(kyber.HashablePoint)
	if !ok {
		return nil, errors.New("point needs to implement `kyber.HashablePoint`")
	}
	Qid := hG2.Hash(ID)
	Gid := s.Pair(master, Qid)

	// 2. Derive random sigma
	sigma := make([]byte, len(msg))
	if _, err := rand.Read(sigma); err != nil {
		return nil, fmt.Errorf("err reading rand sigma: %v", err)
	}
	// 3. Derive r from sigma and msg
	r, err := h3(s, sigma, msg)
	if err != nil {
		return nil, err
	}
	// 4. Compute U = rP
	U := s.G1().Point().Mul(r, s.G1().Point().Base())

	// 5. Compute V = sigma XOR H2(rGid)
	rGid := Gid.Mul(r, Gid) // even in Gt, it's additive notation
	hrGid, err := gtToHash(s, rGid, len(msg), H2Tag())
	if err != nil {
		return nil, err
	}
	V := xor(sigma, hrGid)

	// 6. Compute M XOR H(sigma)
	hsigma, err := h4(s, sigma, len(msg))
	if err != nil {
		return nil, err
	}
	W := xor(msg, hsigma)

	return &Ciphertext{
		U: U,
		V: V,
		W: W,
	}, nil
}

func Decrypt(s pairing.Suite, private kyber.Point, c *Ciphertext) ([]byte, error) {
	// 1. Compute sigma = V XOR H2(e(rP,private))
	gidt := s.Pair(c.U, private)
	hgidt, err := gtToHash(s, gidt, len(c.W), H2Tag())
	if err != nil {
		return nil, err
	}
	if len(hgidt) != len(c.V) {
		return nil, fmt.Errorf("XorSigma is of invalid length: exp %d vs got %d", len(hgidt), len(c.V))
	}
	sigma := xor(hgidt, c.V)

	// 2. Compute M = W XOR H4(sigma)
	hsigma, err := h4(s, sigma, len(c.W))
	if err != nil {
		return nil, err
	}

	msg := xor(hsigma, c.W)

	// 3. Check U = rP
	r, err := h3(s, sigma, msg)
	if err != nil {
		return nil, err
	}
	rP := s.G1().Point().Mul(r, s.G1().Point().Base())
	if !rP.Equal(c.U) {
		return nil, fmt.Errorf("invalid proof: rP check failed")
	}
	return msg, nil

}

// hash sigma and msg to get r
func h3(s pairing.Suite, sigma, msg []byte) (kyber.Scalar, error) {
	h3 := s.Hash()
	h3.Reset()

	if _, err := h3.Write(H3Tag()); err != nil {
		return nil, fmt.Errorf("err hashing h3 tag: %v", err)
	}
	if _, err := h3.Write(sigma); err != nil {
		return nil, fmt.Errorf("err hashing sigma to XOF: %v", err)
	}
	_, _ = h3.Write(msg)
	hashable, ok := s.G1().Scalar().(kyber.HashableScalar)
	if !ok {
		panic("scalar can't be created from hash")
	}

	h3Reader := bytes.NewReader(h3.Sum(make([]byte, h3.Size())))

	return hashable.Hash(s, h3Reader)
}

func h4(s pairing.Suite, sigma []byte, length int) ([]byte, error) {
	h4 := s.Hash()
	h4.Reset()

	if _, err := h4.Write(H4Tag()); err != nil {
		return nil, fmt.Errorf("err writing h4tag: %v", err)
	}
	if _, err := h4.Write(sigma); err != nil {
		return nil, fmt.Errorf("err writing sigma to h4: %v", err)
	}

	h4Reader := bytes.NewReader(h4.Sum(make([]byte, h4.Size())))
	h4sigma := make([]byte, length)

	if _, err := h4Reader.Read(h4sigma); err != nil {
		return nil, fmt.Errorf("err reading from h4: %v", err)
	}
	return h4sigma, nil
}

func gtToHash(s pairing.Suite, gt kyber.Point, length int, dst []byte) ([]byte, error) {
	hash := s.Hash()
	hash.Reset()

	if _, err := hash.Write(dst); err != nil {
		return nil, errors.New("err writing dst to gtHash")
	}
	if _, err := gt.MarshalTo(hash); err != nil {
		return nil, errors.New("err marshalling gt to the hash function")
	}

	hashReader := bytes.NewReader(hash.Sum(make([]byte, hash.Size())))
	var b = make([]byte, length)
	if _, err := hashReader.Read(b); err != nil {
		return nil, errors.New("couldn't read from xof")
	}
	return b[:], nil
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("wrong xor input")
	}
	res := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		res[i] = a[i] ^ b[i]
	}
	return res
}
