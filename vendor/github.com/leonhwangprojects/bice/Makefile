# Copyright 2025 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

.PHONY: test
test:
	@go clean -testcache
	GOEXPERIMENT=nocoverageredesign go test -race -timeout 60s -coverpkg=./... -coverprofile=coverage.raw.txt -covermode atomic ./...
	@cat coverage.raw.txt | grep -Ev "internal/" > coverage.txt
	go tool cover -func=coverage.txt
	@rm -f coverage.raw.txt coverage.txt
	@go clean -testcache
