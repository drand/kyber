package bn254

import (
	"testing"

	"github.com/drand/kyber/sign/bls" //nolint:staticcheck // Testing deprecated but still functional BLS package
	"github.com/drand/kyber/sign/test"
)

func TestBLSSchemeBN254G1(t *testing.T) {
	suite := NewSuite()
	s := bls.NewSchemeOnG1(suite)
	test.SchemeTesting(t, s)
}
