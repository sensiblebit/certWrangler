#!/usr/bin/env bash

# go to git root
cd "$(git rev-parse --show-toplevel)" || exit 1

# upgrade all dependencies, and use the latest go version
brew upgrade go
go version
go get -u ./..
go mod download
go mod tidy

# build the certwrangler tool
go build -o certwrangler main.go