build:
	go build -o backend.exe ./cmd

run:
	./backend

test:
	go test -v ./...