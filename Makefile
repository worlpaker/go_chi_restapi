build:
	go build -o backend.exe ./cmd

run:
	./backend

test:
	go test -v ./...
	
cover:
	go test ./... -coverprofile="coverage.out" -coverpkg ./... && go tool cover -html="coverage.out"