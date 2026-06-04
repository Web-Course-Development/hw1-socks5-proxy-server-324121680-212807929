package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

const (
	socksVersion = 0x05
	authVersion  = 0x01 // username/password sub-negotiation version (RFC 1929)

	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNoAccept = 0xFF

	cmdConnect = 0x01
	atypIPv4   = 0x01
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

	method, err := negotiateAuth(conn)
	if err != nil {
		return
	}

	if method == methodUserPass {
		if err := authenticateUserPass(conn); err != nil {
			return
		}
	}

	handleConnect(conn)
}

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

	conn.Write([]byte{socksVersion, methodNoAccept})
	return 0, fmt.Errorf("no acceptable auth method")
}

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

func handleConnect(conn net.Conn) {
	head := make([]byte, 4) // VER, CMD, RSV, ATYP
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	if head[1] != cmdConnect {
		reply(conn, 0x07) // command not supported
		return
	}

	host, err := readAddress(conn, head[3])
	if err != nil {
		reply(conn, 0x08) // address type not supported
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	target, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		reply(conn, 0x05) // could not reach the target
		return
	}
	defer target.Close()

	reply(conn, 0x00) // success
	relay(conn, target)
}

// readAddress reads DST.ADDR. only IPv4 for now (domain comes next).
func readAddress(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

func reply(conn net.Conn, code byte) {
	conn.Write([]byte{socksVersion, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
}

func relay(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(target, client)
		closeWrite(target) // tell the target we're done sending
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, target)
		closeWrite(client) // let the client see EOF so HTTP can finish
	}()
	wg.Wait()
}

func closeWrite(conn net.Conn) {
	if c, ok := conn.(interface{ CloseWrite() error }); ok {
		c.CloseWrite()
	}
}

func offers(methods []byte, want byte) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}
