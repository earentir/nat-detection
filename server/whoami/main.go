package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("who‑am‑I server listening on :8080")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		addr := conn.RemoteAddr().(*net.TCPAddr)
		fmt.Fprintf(conn, "%s:%d\n", addr.IP, addr.Port)
		conn.Close()
	}
}
