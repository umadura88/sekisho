.PHONY: build test lint clean

build:
	go build -o bin/trapgen ./cmd/trapgen
	go build -o bin/sekisho ./cmd/sekisho

test:
	go test -race ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; running go vet instead"; \
		go vet ./...; \
	fi

clean:
	rm -rf bin
