module github.com/drand/kyber

go 1.13

require (
	github.com/drand/kyber-bls12381 v0.1.0
	github.com/jonboulle/clockwork v0.1.0
	github.com/stretchr/testify v1.4.0
	go.dedis.ch/fixbuf v1.0.3
	go.dedis.ch/protobuf v1.0.11
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	golang.org/x/sys v0.0.0-20200602225109-6fdc65e7d980
)

replace github.com/drand/kyber-bls12381 => ../kyber-bls12381
