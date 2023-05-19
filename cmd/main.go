package main

import (
	"backend/api/server"
	"backend/config"
)

func main() {
	panic(server.Start(config.ServerPort))
}
