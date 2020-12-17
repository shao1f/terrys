package main

import (
	"fmt"
	"log"
	"time"

	"github.com/terrys/client"
	"github.com/terrys/server"
)

func main() {
	go Server()
	time.Sleep(time.Second * 5)
	go Cli()
	fmt.Println("start success")
	select {}
}

func Cli() {
	cli, err := client.NewClient(":1080", "127.0.0.1:9005", "hello", 500)
	if err != nil {
		log.Fatal(err)
	}
	err = cli.ListenAndServer()
	if err != nil {
		log.Fatal(err)
	}
}

func Server() {
	srv, err := server.NewServer(":9005", "hello", 500)
	if err != nil {
		log.Fatal(err)
	}
	err = srv.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
