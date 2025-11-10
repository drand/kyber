.DEFAULT_GOAL := test

.PHONY: fetch-dependencies
fetch-dependencies:
	go get -v -t ./...

.PHONY: test
test: fetch-dependencies
	go test -race -v ./...
