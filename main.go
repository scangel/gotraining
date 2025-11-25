package main

import "log"

func main() {
	server := NewServer(":8080")

	log.Fatal(server.Start())
}
