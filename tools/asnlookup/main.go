package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: asnlookup <ip> [...]")
		os.Exit(1)
	}
	for _, ip := range os.Args[1:] {
		asn, name, err := cymruASN(ip)
		if err != nil {
			fmt.Printf("%s: %v\n", ip, err)
			continue
		}
		fmt.Printf("%s → AS%d (%s)\n", ip, asn, name)
	}
}

func cymruASN(ip string) (uint, string, error) {
	conn, err := net.Dial("tcp", "whois.cymru.com:43")
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	fmt.Fprintf(conn, " -f -o -p %s\n", ip)
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "AS") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 7 {
			continue
		}
		var asn uint
		fmt.Sscanf(parts[0], "%d", &asn)
		name := strings.TrimSpace(parts[6])
		return asn, name, nil
	}
	return 0, "", fmt.Errorf("no data")
}
