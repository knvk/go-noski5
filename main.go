package main

import (
	socks5 "noski5/socks"
)

func main() {
	srv := socks5.Server{
		Addr:    ":8000",
		Network: "tcp",
	}

	srv.ListenAndServe()

	// if you want run concurently use select {}

}
