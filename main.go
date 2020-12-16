package main

import (
	"log"

	"github.com/terrys/client"
)

func main() {
	cli, err := client.NewClient(":1080", "49.232.192.87:9005", "", 0, 0)
	if err != nil {
		log.Fatal(err)
	}
	err = cli.ListenAndServer()
	if err != nil {
		log.Fatal(err)
	}
}
