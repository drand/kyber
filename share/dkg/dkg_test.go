package dkg

import (
	"testing"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/edwards25519"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/sign/tbls"
	"github.com/drand/kyber/util/random"
	clock "github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

type TestNode struct {
	Index   uint32
	Private kyber.Scalar
	Public  kyber.Point
	dkg     *DistKeyGenerator
	res     *Result
	proto   *Protocol
	phaser  *TimePhaser
	board   *TestBoard
	clock   clock.FakeClock
}

func NewTestNode(s Suite, index int) *TestNode {
	private := s.Scalar().Pick(random.New())
	public := s.Point().Mul(private, nil)
	return &TestNode{
		Index:   uint32(index),
		Private: private,
		Public:  public,
	}
}

func GenerateTestNodes(s Suite, n int) []*TestNode {
	tns := make([]*TestNode, n)
	for i := 0; i < n; i++ {
		tns[i] = NewTestNode(s, i)
	}
	return tns
}

func NodesFromTest(tns []*TestNode) []Node {
	nodes := make([]Node, len(tns))
	for i := 0; i < len(tns); i++ {
		nodes[i] = Node{
			Index:  tns[i].Index,
			Public: tns[i].Public,
		}
	}
	return nodes
}

// inits the dkg structure
func SetupNodes(nodes []*TestNode, c *DkgConfig) {
	nonce, _ := GetNonce()
	for _, n := range nodes {
		c2 := *c
		c2.Longterm = n.Private
		c2.Nonce = nonce
		dkg, err := NewDistKeyHandler(&c2)
		if err != nil {
			panic(err)
		}
		n.dkg = dkg
	}
}

func SetupReshareNodes(nodes []*TestNode, c *DkgConfig, coeffs []kyber.Point) {
	nonce, _ := GetNonce()
	for _, n := range nodes {
		c2 := *c
		c2.Longterm = n.Private
		c2.Nonce = nonce
		if n.res != nil {
			c2.Share = n.res.Key
		} else {
			c2.PublicCoeffs = coeffs
		}
		dkg, err := NewDistKeyHandler(&c2)
		if err != nil {
			panic(err)
		}
		n.dkg = dkg
	}
}

func IsDealerIncluded(bundles []*ResponseBundle, dealer uint32) bool {
	for _, bundle := range bundles {
		for _, resp := range bundle.Responses {
			if resp.DealerIndex == dealer {
				return true
			}
		}
	}
	return false
}

func testResults(t *testing.T, suite Suite, thr, n int, results []*Result) {
	// test if all results are consistent
	for i, res := range results {
		require.Equal(t, thr, len(res.Key.Commitments()))
		for j, res2 := range results {
			if i == j {
				continue
			}
			require.True(t, res.PublicEqual(res2), "res %+v != %+v", res, res2)
		}
	}
	// test if re-creating secret key gives same public key
	var shares []*share.PriShare
	for _, res := range results {
		shares = append(shares, res.Key.PriShare())
	}
	// test if shares are public polynomial evaluation
	exp := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commitments())
	for _, share := range shares {
		pubShare := exp.Eval(share.I)
		expShare := suite.Point().Mul(share.V, nil)
		require.True(t, pubShare.V.Equal(expShare), "share %s give pub %s vs exp %s", share.V.String(), pubShare.V.String(), expShare.String())
	}

	secretPoly, err := share.RecoverPriPoly(suite, shares, thr, n)
	require.NoError(t, err)
	gotPub := secretPoly.Commit(suite.Point().Base())
	require.True(t, exp.Equal(gotPub))

	secret, err := share.RecoverSecret(suite, shares, thr, n)
	require.NoError(t, err)
	public := suite.Point().Mul(secret, nil)
	expKey := results[0].Key.Public()
	require.True(t, public.Equal(expKey))

}

type MapDeal func([]*DealBundle) []*DealBundle
type MapResponse func([]*ResponseBundle) []*ResponseBundle
type MapJustif func([]*JustificationBundle) []*JustificationBundle

func RunDKG(t *testing.T, tns []*TestNode, conf DkgConfig,
	dm MapDeal, rm MapResponse, jm MapJustif) []*Result {

	SetupNodes(tns, &conf)
	var deals []*DealBundle
	for _, node := range tns {
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	if dm != nil {
		deals = dm(deals)
	}

	var respBundles []*ResponseBundle
	for _, node := range tns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		if resp != nil {
			respBundles = append(respBundles, resp)
		}
	}

	if rm != nil {
		respBundles = rm(respBundles)
	}

	var justifs []*JustificationBundle
	var results []*Result
	for _, node := range tns {
		res, just, err := node.dkg.ProcessResponses(respBundles)
		require.NoError(t, err)
		if res != nil {
			results = append(results, res)
		} else if just != nil {
			justifs = append(justifs, just)
		}
	}

	if len(justifs) == 0 {
		return results
	}

	if jm != nil {
		justifs = jm(justifs)
	}

	for _, node := range tns {
		res, err := node.dkg.ProcessJustifications(justifs)
		require.NoError(t, err)
		require.NotNil(t, res)
		results = append(results, res)
	}
	return results
}

func TestDKGFull(t *testing.T) {
	n := 5
	thr := n
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := DkgConfig{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
	}

	results := RunDKG(t, tns, conf, nil, nil, nil)
	testResults(t, suite, thr, n, results)
}

func TestDKGThreshold(t *testing.T) {
	n := 5
	thr := 4
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := DkgConfig{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
	}

	dm := func(deals []*DealBundle) []*DealBundle {
		// we make first dealer absent
		deals = deals[1:]
		require.Len(t, deals, n-1)
		// we make the second dealer creating a invalid share for 3rd participant
		deals[0].Deals[2].EncryptedShare = []byte("Another one bites the dust")
		return deals
	}
	rm := func(resp []*ResponseBundle) []*ResponseBundle {
		for _, bundle := range resp {
			// first dealer should not see anything bad
			require.NotEqual(t, 0, bundle.ShareIndex)
		}
		// we must find at least a complaint about node 0
		require.True(t, IsDealerIncluded(resp, 0))
		// if we are checking responses from node 2, then it must also
		// include a complaint for node 1
		require.True(t, IsDealerIncluded(resp, 1))
		return resp
	}
	jm := func(justs []*JustificationBundle) []*JustificationBundle {
		var found0 bool
		var found1 bool
		for _, bundle := range justs {
			found0 = found0 || bundle.DealerIndex == 0
			found1 = found1 || bundle.DealerIndex == 1
		}
		require.True(t, found0 && found1)
		return justs
	}
	results := RunDKG(t, tns, conf, dm, rm, jm)
	var filtered = results[:0]
	for _, n := range tns {
		if 0 == n.Index {
			// node 0 is excluded by all others since he didn't even provide a
			// deal at the first phase,i.e. it didn't even provide a public
			// polynomial at the first phase.
			continue
		}
		for _, res := range results {
			if res.Key.Share.I != int(n.Index) {
				continue
			}
			for _, nodeQual := range res.QUAL {
				require.NotEqual(t, uint32(0), nodeQual.Index)
			}
			filtered = append(filtered, res)
		}
	}
	testResults(t, suite, thr, n, filtered)
}

func TestDKGResharing(t *testing.T) {
	n := 5
	thr := 4
	var suite = bn256.NewSuiteG2()
	var sigSuite = bn256.NewSuiteG1()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := DkgConfig{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
	}
	SetupNodes(tns, &conf)

	var deals []*DealBundle
	for _, node := range tns {
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	for _, node := range tns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		// for a full perfect dkg there should not be any complaints
		require.Nil(t, resp)
	}

	var results []*Result
	for _, node := range tns {
		// we give no responses
		res, just, err := node.dkg.ProcessResponses(nil)
		require.NoError(t, err)
		require.Nil(t, just)
		require.NotNil(t, res)
		results = append(results, res)
		node.res = res
	}
	testResults(t, suite, thr, n, results)

	// create a partial signature with the share now and make sure the partial
	// signature is verifiable and then *not* verifiable after the resharing
	oldShare := results[0].Key.Share
	msg := []byte("Hello World")
	scheme := tbls.NewThresholdSchemeOnG1(sigSuite)
	oldPartial, err := scheme.Sign(oldShare, msg)
	require.NoError(t, err)
	poly := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commits)
	require.NoError(t, scheme.VerifyPartial(poly, msg, oldPartial))

	// we setup now the second group with higher node count and higher threshold
	// and we remove one node from the previous group
	newN := n + 5
	newT := thr + 4
	var newTns = make([]*TestNode, newN)
	// remove the last node from the previous group
	offline := 1
	copy(newTns, tns[:n-offline])
	// + offline because we fill the gap of the offline nodes by new nodes
	newNode := newN - n + offline
	for i := 0; i < newNode; i++ {
		//  new node can have the same index as a previous one, separation is made
		newTns[n-1+i] = NewTestNode(suite, n-1+i)
	}
	newList := NodesFromTest(newTns)
	newConf := &DkgConfig{
		Suite:        suite,
		NewNodes:     newList,
		OldNodes:     list,
		Threshold:    newT,
		OldThreshold: thr,
	}

	SetupReshareNodes(newTns, newConf, tns[0].res.Key.Commits)

	deals = nil
	for _, node := range newTns {
		if node.res == nil {
			// new members don't issue deals
			continue
		}
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	var responses []*ResponseBundle
	for _, node := range newTns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		if resp != nil {
			// last node from the old group is not present so there should be
			// some responses !
			responses = append(responses, resp)
		}
	}
	require.True(t, len(responses) > 0)

	results = nil
	for _, node := range newTns {
		res, just, err := node.dkg.ProcessResponses(responses)
		require.NoError(t, err)
		require.Nil(t, res)
		// since the last old node is absent he can't give any justifications
		require.Nil(t, just)
	}

	for _, node := range newTns {
		res, err := node.dkg.ProcessJustifications(nil)
		require.NoError(t, err)
		require.NotNil(t, res)
		results = append(results, res)
	}
	testResults(t, suite, newT, newN, results)

	// test a tbls signature is correct
	newShare := results[0].Key.Share
	newPartial, err := scheme.Sign(newShare, msg)
	require.NoError(t, err)
	newPoly := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commits)
	require.NoError(t, scheme.VerifyPartial(newPoly, msg, newPartial))
	// test we can not verify the old partial with the new public polynomial
	require.Error(t, scheme.VerifyPartial(poly, msg, newPartial))
}

func TestDKGFullFast(t *testing.T) {
	n := 5
	thr := n
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := DkgConfig{
		FastSync:  true,
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
	}

	results := RunDKG(t, tns, conf, nil, nil, nil)
	testResults(t, suite, thr, n, results)
}

func TestDKGNonceInvalid(t *testing.T) {
	n := 5
	thr := n
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := &DkgConfig{
		FastSync:  true,
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
	}
	nonce, _ := GetNonce()
	conf.Nonce = nonce
	conf.Longterm = tns[0].Private
	conf.Nonce = nonce
	dkg, err := NewDistKeyHandler(conf)
	require.NoError(t, err)
	require.NotNil(t, dkg)

	conf.Nonce = []byte("that's some bad nonce")
	dkg, err = NewDistKeyHandler(conf)
	require.Error(t, err)
	require.Nil(t, dkg)
}

func TestDKGNonceInvalidEviction(t *testing.T) {
	n := 7
	thr := 4
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := DkgConfig{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
	}

	genPublic := func() []kyber.Point {
		points := make([]kyber.Point, thr)
		for i := 0; i < thr; i++ {
			points[i] = suite.Point().Pick(random.New())
		}
		return points
	}

	dm := func(deals []*DealBundle) []*DealBundle {
		deals[0].SessionID = []byte("Beat It")
		require.Equal(t, deals[0].DealerIndex, Index(0))
		// change the public polynomial so it trigggers a response and a
		// justification
		deals[1].Public = genPublic()
		require.Equal(t, deals[1].DealerIndex, Index(1))
		return deals
	}
	rm := func(resp []*ResponseBundle) []*ResponseBundle {
		for _, bundle := range resp {
			for _, r := range bundle.Responses {
				// he's evicted so there's not even a complaint
				require.NotEqual(t, 0, r.DealerIndex)
			}
			if bundle.ShareIndex == 2 {
				bundle.SessionID = []byte("Billie Jean")
			}
		}
		return resp
	}
	jm := func(just []*JustificationBundle) []*JustificationBundle {
		require.Len(t, just, 1)
		just[0].SessionID = []byte("Free")
		return just
	}

	results := RunDKG(t, tns, conf, dm, rm, jm)
	// make sure the first, second, and third node are not here
	isEvicted := func(i Index) bool {
		return i == 0 || i == 1 || i == 2
	}
	filtered := results[:0]
	for _, r := range results {
		if isEvicted(Index(r.Key.Share.I)) {
			continue
		}
		require.NotContains(t, r.QUAL, Index(0))
		require.NotContains(t, r.QUAL, Index(1))
		require.NotContains(t, r.QUAL, Index(2))
		filtered = append(filtered, r)
	}
	testResults(t, suite, thr, n, filtered)
}
