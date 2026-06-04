package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const (
	socksVersion = 0x05
	authVersion  = 0x01 // username/password sub-negotiation version (RFC 1929)

	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNoAccept = 0xFF
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn) // one goroutine per client
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 1. greeting + pick the auth method
	method, err := negotiateAuth(conn)
	if err != nil {
		return
	}

	// 2. username/password sub-negotiation if we asked for it
	if method == methodUserPass {
		if err := authenticateUserPass(conn); err != nil {
			return
		}
	}

	// TODO next stage: read CONNECT, dial the target, reply, relay
}

// negotiateAuth reads the client greeting and replies with the method we want.
// no-auth by default; username/password when PROXY_USER is set.
func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2) // VER, NMETHODS
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}
	if header[0] != socksVersion {
		return 0, fmt.Errorf("bad socks version %d", header[0])
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	want := byte(methodNoAuth)
	if os.Getenv("PROXY_USER") != "" {
		want = methodUserPass
	}

	if offers(methods, want) {
		conn.Write([]byte{socksVersion, want})
		return want, nil
	}

	// client doesn't offer the method we need
	conn.Write([]byte{socksVersion, methodNoAccept})
	return 0, fmt.Errorf("no acceptable auth method")
}

// authenticateUserPass runs the RFC 1929 sub-negotiation (version byte 0x01).
func authenticateUserPass(conn net.Conn) error {
	head := make([]byte, 2) // VER, ULEN
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != authVersion {
		return fmt.Errorf("bad auth version %d", head[0])
	}

	user := make([]byte, head[1])
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}

	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	if string(user) == os.Getenv("PROXY_USER") && string(pass) == os.Getenv("PROXY_PASS") {
		conn.Write([]byte{authVersion, 0x00}) // success
		return nil
	}
	conn.Write([]byte{authVersion, 0x01}) // failure (non-zero status)
	return fmt.Errorf("bad credentials")
}

// offers reports whether the client offered the auth method we want.
func offers(methods []byte, want byte) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}
