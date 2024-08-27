package bdn

import (
	"encoding"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/drand/kyber"
	bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

// Reference test for other languages
func TestBDN_HashPointToR_BN256(t *testing.T) {
	suite := bn256.NewSuiteBn256()
	schemeOnG1 := NewSchemeOnG1(suite)
	two := suite.Scalar().Add(suite.Scalar().One(), suite.Scalar().One())
	three := suite.Scalar().Add(two, suite.Scalar().One())

	p1 := suite.Point().Base()
	p2 := suite.Point().Mul(two, suite.Point().Base())
	p3 := suite.Point().Mul(three, suite.Point().Base())

	coefs, err := hashPointToR([]kyber.Point{p1, p2, p3})

	require.NoError(t, err)
	require.Equal(t, "35b5b395f58aba3b192fb7e1e5f2abd3", coefs[0].String())
	require.Equal(t, "14dcc79d46b09b93075266e47cd4b19e", coefs[1].String())
	require.Equal(t, "933f6013eb3f654f9489d6d45ad04eaf", coefs[2].String())
	require.Equal(t, 16, coefs[0].MarshalSize())

	mask, _ := sign.NewMask(suite, []kyber.Point{p1, p2, p3}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	mask.SetBit(2, true)

	agg, err := schemeOnG1.AggregatePublicKeys(mask)
	require.NoError(t, err)

	buf, err := agg.MarshalBinary()
	require.NoError(t, err)
	ref := "1432ef60379c6549f7e0dbaf289cb45487c9d7da91fc20648f319a9fbebb23164abea76cdf7b1a3d20d539d9fe096b1d6fb3ee31bf1d426cd4a0d09d603b09f55f473fde972aa27aa991c249e890c1e4a678d470592dd09782d0fb3774834f0b2e20074a49870f039848a6b1aff95e1a1f8170163c77098e1f3530744d1826ce"
	require.Equal(t, ref, fmt.Sprintf("%x", buf))
}

var testsOnSchemes = []struct {
	name string
	test func(t *testing.T, suite pairing.Suite, scheme *Scheme)
}{
	{"aggregateSignatures", aggregateSignatures},
	{"subsetSignature", subsetSignature},
	{"rogueAttack", rogueAttack},
}

func TestBDN(t *testing.T) {
	run := func(name string, suite pairing.Suite, schemeGen func(pairing.Suite) *Scheme) {
		for _, ts := range testsOnSchemes {
			t.Run(name+"/"+ts.name, func(t *testing.T) {
				ts.test(t, suite, schemeGen(suite))
			})
		}
	}

	run("bn256/G1", bn256.NewSuite(), NewSchemeOnG1)
	//run("bn256/G2", bn256.NewSuite(), NewSchemeOnG2) // G2 does not support hash to point https://github.com/dedis/kyber/pull/428
	run("bls12/G1", bls12381.NewBLS12381Suite(), NewSchemeOnG1)
	run("bls12/G2", bls12381.NewBLS12381Suite(), NewSchemeOnG2)

}

func aggregateSignatures(t *testing.T, suite pairing.Suite, scheme *Scheme) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg)
	require.NoError(t, err)
	sig2, err := scheme.Sign(private2, msg)
	require.NoError(t, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)

	_, err = scheme.AggregateSignatures([][]byte{sig1}, mask)
	require.Error(t, err)

	aggregatedSig, err := scheme.AggregateSignatures([][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := scheme.AggregatePublicKeys(mask)
	require.NoError(t, err)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = scheme.Verify(aggregatedKey, msg, sig)
	require.NoError(t, err)

	mask.SetBit(1, false)
	aggregatedKey, err = scheme.AggregatePublicKeys(mask)
	require.NoError(t, err)

	err = scheme.Verify(aggregatedKey, msg, sig)
	require.Error(t, err)
}

func subsetSignature(t *testing.T, suite pairing.Suite, scheme *Scheme) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	_, public3 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg)
	require.NoError(t, err)
	sig2, err := scheme.Sign(private2, msg)
	require.NoError(t, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public3, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(2, true)

	aggregatedSig, err := scheme.AggregateSignatures([][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := scheme.AggregatePublicKeys(mask)
	require.NoError(t, err)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = scheme.Verify(aggregatedKey, msg, sig)
	require.NoError(t, err)
}

func rogueAttack(t *testing.T, suite pairing.Suite, scheme *Scheme) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	// honest
	_, public1 := scheme.NewKeyPair(random.New())
	// attacker
	private2, public2 := scheme.NewKeyPair(random.New())

	// create a forged public-key for public1
	rogue := public1.Clone().Sub(public2, public1)

	pubs := []kyber.Point{public1, rogue}

	sig, err := scheme.Sign(private2, msg)
	require.NoError(t, err)

	// Old scheme not resistant to the attack
	agg := scheme.blsScheme.AggregatePublicKeys(pubs...)
	require.NoError(t, scheme.Verify(agg, msg, sig))

	// New scheme that should detect
	mask, _ := sign.NewMask(suite, pubs, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	agg, err = scheme.AggregatePublicKeys(mask)
	require.NoError(t, err)
	require.Error(t, scheme.Verify(agg, msg, sig))
}

func Benchmark_BDN_AggregateSigs(b *testing.B) {
	suite := bn256.NewSuite()
	schemeOnG1 := NewSchemeOnG1(suite)
	private1, public1 := schemeOnG1.NewKeyPair(random.New())
	private2, public2 := schemeOnG1.NewKeyPair(random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := schemeOnG1.Sign(private1, msg)
	require.Nil(b, err)
	sig2, err := schemeOnG1.Sign(private2, msg)
	require.Nil(b, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		schemeOnG1.AggregateSignatures([][]byte{sig1, sig2}, mask)
	}
}

func Benchmark_BDN_BLS12381_AggregateVerify(b *testing.B) {
	suite := bls12381.NewBLS12381Suite()
	schemeOnG2 := NewSchemeOnG2(suite)

	rng := random.New()
	pubKeys := make([]kyber.Point, 3000)
	privKeys := make([]kyber.Scalar, 3000)
	for i := range pubKeys {
		privKeys[i], pubKeys[i] = schemeOnG2.NewKeyPair(rng)
	}

	baseMask, err := sign.NewMask(suite, pubKeys, nil)
	require.NoError(b, err)
	mask, err := NewCachedMask(baseMask)
	require.NoError(b, err)
	for i := range pubKeys {
		require.NoError(b, mask.SetBit(i, true))
	}

	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sigs := make([][]byte, len(privKeys))
	for i, k := range privKeys {
		s, err := schemeOnG2.Sign(k, msg)
		require.NoError(b, err)
		sigs[i] = s
	}

	sig, err := schemeOnG2.AggregateSignatures(sigs, mask)
	require.NoError(b, err)
	sigb, err := sig.MarshalBinary()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk, err := schemeOnG2.AggregatePublicKeys(mask)
		require.NoError(b, err)
		require.NoError(b, schemeOnG2.Verify(pk, msg, sigb))
	}
}

func unmarshalHex[T encoding.BinaryUnmarshaler](t *testing.T, into T, s string) T {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.NoError(t, into.UnmarshalBinary(b))
	return into
}

// This tests exists to make sure we don't accidentally make breaking changes to signature
// aggregation by using checking against known aggregated signatures and keys.
func TestBDNFixtures(t *testing.T) {
	suite := bn256.NewSuite()
	schemeOnG1 := NewSchemeOnG1(suite)

	public1 := unmarshalHex(t, suite.G2().Point(), "1a30714035c7a161e286e54c191b8c68345bd8239c74925a26290e8e1ae97ed6657958a17dca12c943fadceb11b824402389ff427179e0f10194da3c1b771c6083797d2b5915ea78123cbdb99ea6389d6d6b67dcb512a2b552c373094ee5693524e3ebb4a176f7efa7285c25c80081d8cb598745978f1a63b886c09a316b1493")
	private1 := unmarshalHex(t, suite.G2().Scalar(), "49cfe5e9f4532670137184d43c0299f8b635bcacf6b0af7cab262494602d9f38")
	public2 := unmarshalHex(t, suite.G2().Point(), "603bc61466ec8762ec6de2ba9a80b9d302d08f580d1685ac45a8e404a6ed549719dc0faf94d896a9983ff23423772720e3de5d800bc200de6f7d7e146162d3183b8880c5c0d8b71ca4b3b40f30c12d8cc0679c81a47c239c6aa7e9cc2edab4a927fe865cd413c1c17e3df8f74108e784cd77dd3e161bdaf30019a55826a32a1f")
	private2 := unmarshalHex(t, suite.G2().Scalar(), "493abea4bb35b74c78ad9245f9d37883aeb6ee91f7fb0d8a8e11abf7aa2be581")
	public3 := unmarshalHex(t, suite.G2().Point(), "56118769a1f0b6286abacaa32109c1497ab0819c5d21f27317e184b6681c283007aa981cb4760de044946febdd6503ab77a4586bc29c04159e53a6fa5dcb9c0261ccd1cb2e28db5204ca829ac9f6be95f957a626544adc34ba3bc542533b6e2f5cbd0567e343641a61a42b63f26c3625f74b66f6f46d17b3bf1688fae4d455ec")
	private3 := unmarshalHex(t, suite.G2().Scalar(), "7fb0ebc317e161502208c3c16a4af890dedc3c7b275e8a04e99c0528aa6a19aa")

	sig1Exp, err := hex.DecodeString("0913b76987be19f943be23b636cab9a2484507717326bd8bbdcdbbb6b8d5eb9253cfb3597c3fa550ee4972a398813650825a871f8e0b242ae5ddbce1b7c0e2a8")
	require.NoError(t, err)
	sig2Exp, err := hex.DecodeString("21195d29b1863bca1559e24375211d1411d8a28a8f4c772870b07f4ccda2fd5e337c1315c210475c683e3aa8b87d3aed3f7255b3087daa30d1e1432dd61d7484")
	require.NoError(t, err)
	sig3Exp, err := hex.DecodeString("3c1ac80345c1733630dbdc8106925c867544b521c259f9fa9678d477e6e5d3d212b09bc0d95137c3dbc0af2241415156c56e757d5577a609293584d045593195")
	require.NoError(t, err)

	aggSigExp := unmarshalHex(t, suite.G1().Point(), "520875e6667e0acf489e458c6c2233d09af81afa3b2045e0ec2435cfc582ba2c44af281d688efcf991d20975ce32c9933a09f8c4b38c18ef4b4510d8fa0f09d7")
	aggKeyExp := unmarshalHex(t, suite.G2().Point(), "394d47291878a81fefb17708c57cf8078b24c46bf4554b3012732acd15395dbf09f13a65e068de766f5449d1de130f09bf09dc35a67f7f822f2a187230e155891d40db3c51afa5b3e05a039c50d04ff9c788718a2887e34644a55a14a2a2679226a3315c281e03367a4d797db819625e0c662d35e45e0e9e7604c104179ae8a7")

	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := schemeOnG1.Sign(private1, msg)
	require.Nil(t, err)
	require.Equal(t, sig1Exp, sig1)

	sig2, err := schemeOnG1.Sign(private2, msg)
	require.Nil(t, err)
	require.Equal(t, sig2Exp, sig2)

	sig3, err := schemeOnG1.Sign(private3, msg)
	require.Nil(t, err)
	require.Equal(t, sig3Exp, sig3)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2, public3}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, false)
	mask.SetBit(2, true)

	aggSig, err := schemeOnG1.AggregateSignatures([][]byte{sig1, sig2, sig3}, mask)
	require.NoError(t, err)
	require.True(t, aggSigExp.Equal(aggSig))

	aggKey, err := schemeOnG1.AggregatePublicKeys(mask)
	require.NoError(t, err)
	require.True(t, aggKeyExp.Equal(aggKey))
}

func TestBDNDeprecatedAPIs(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)

	_, err = AggregateSignatures(suite, [][]byte{sig1}, mask)
	require.Error(t, err)

	aggregatedSig, err := AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := AggregatePublicKeys(suite, mask)
	require.NoError(t, err)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)

	mask.SetBit(1, false)
	aggregatedKey, err = AggregatePublicKeys(suite, mask)
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.Error(t, err)
}
