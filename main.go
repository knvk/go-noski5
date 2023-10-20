package main

import (
	"bufio"
	"log"
	"os"
	"strings"

	socks5 "github.com/knvk/go-noski5/socks"
)

func main() {
	if len(os.Args) < 2 {
		println("usage: ./noski5 <cred-file>")
		return
	}
	fp := os.Args[1]

	file, err := os.Open(fp)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	creds := make(map[string]string)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		creds[parts[0]] = parts[1]
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	authMethod := socks5.PassAuthMethod{Credentials: creds}
	//authMethod := socks5.NoAuthMethod{}

	srv := socks5.NewSocksServ(":8000", "tcp", authMethod)

	srv.ListenAndServe()

}
