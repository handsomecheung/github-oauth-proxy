#!/bin/bash
set -e

export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0

go get github.com/bitly/go-simplejson
go get github.com/gorilla/mux

go build
