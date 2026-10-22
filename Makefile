.PHONY: build clean cross release

BINARY := emudhra-scanner
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o $(BINARY) .

clean:
	rm -f $(BINARY) $(BINARY)-*

cross:
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(BINARY)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $(BINARY)-linux-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(BINARY)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $(BINARY)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(BINARY)-windows-amd64.exe .
	GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $(BINARY)-windows-arm64.exe .
	GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(BINARY)-freebsd-amd64 .
	@echo "Built:"
	@ls -la $(BINARY)-*

# Local smoke test
test-run: build
	./$(BINARY) version
	./$(BINARY) info
	./$(BINARY) check -timeout 5s || true
