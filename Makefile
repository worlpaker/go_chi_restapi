build:
	go build -o backend.exe ./cmd

run:
	./backend

test:
	go test -v ./...
	
cover:
	go test ./... -coverprofile="coverage.out" -coverpkg ./... && go tool cover -html="coverage.out"

# make sure you have installed swag before, see: https://github.com/swaggo/swag
swag-init:
	swag init -g ./cmd/main.go -o ./api/docs