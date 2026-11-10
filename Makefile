BIN := vaultshare

.PHONY: all build run test clean clean-data

all: build

# Create the Go module (and fetch golang.org/x/crypto) the first time.
go.mod:
	go mod init $(BIN)
	go mod tidy

build: go.mod
	go build -o $(BIN) .

run: build
	./$(BIN)

test: go.mod
	go test ./...

# Remove the compiled program.
clean:
	rm -f $(BIN)

# Remove everything the program writes: identities, vault entries, packages, extracted files.
clean-data:
	rm -f *.identity.json *.pub.json *.vault.json *.share.json extracted-* received-*