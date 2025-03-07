package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"log"
)

var listenPort = "1081"

// Addr represents a SOCKS5 destination address
type Addr struct {
	Atyp byte   // Address type (0x01: IPv4, 0x03: Domain, 0x04: IPv6)
	Addr []byte // Address bytes
	Port uint16 // Port number
}

// String formats the address for logging
func (a Addr) String() string {
	switch a.Atyp {
	case 0x01: // IPv4
		return fmt.Sprintf("%s:%d", net.IP(a.Addr).String(), a.Port)
	case 0x03: // Domain
		return fmt.Sprintf("%s:%d", string(a.Addr), a.Port)
	case 0x04: // IPv6
		return fmt.Sprintf("[%s]:%d", net.IP(a.Addr).String(), a.Port)
	default:
		return "unknown"
	}
}

func main() {
	// Parse command-line flags
	var localAddr string
	var upstream string
	flag.StringVar(&localAddr, "listen", "[::1]:"+listenPort, "Local address to listen on (e.g., [::1]:"+listenPort+" for IPv6)")
	flag.StringVar(&upstream, "upstream", "", "Upstream SOCKS5 proxy (e.g., 127.0.0.1:"+listenPort+"), leave empty for direct connection")
	flag.Parse()

	// Set up TCP listener
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on %s: %v\n", localAddr, err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("SOCKS5 server running on %s\n", localAddr)

	// Accept incoming connections
	for {
		client, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept failed: %v\n", err)
			continue
		}
		fmt.Printf("New connection from %s\n", client.RemoteAddr().String())
		go handleClient(client, upstream)
	}
}
// handleClient processes a single client connection
func handleClient(client net.Conn, upstream string) {
	defer client.Close()

	// Perform SOCKS5 handshake
	err := handleHandshake(client)
	if err != nil {
		fmt.Println("Handshake failed:", err)
		return
	}

	// Read the client's request
	destAddr, err := readAddr(client)
	if err != nil {
		fmt.Println("Read request failed:", err)
		return
	}

	// Print the request details
	log.Printf("Request: %s\n", destAddr.String())

	// Lookup IPs for the given address (assumes destAddr.Addr is a domain name)
	ipsToCheck, err := net.LookupIP(string(destAddr.Addr))
	if err != nil {
		log.Println("LookupIP error:", err)
	}
	
	// Prefer IPv4, if not, use the first available IP (IPv6)
	var ipToUse string
	for _, ip := range ipsToCheck {
		if ip.To4() != nil {
			ipToUse = ip.String()
			break
		}
	}
	if ipToUse == "" && len(ipsToCheck) > 0 {
		ipToUse = ipsToCheck[0].String()
	}

	port := destAddr.Port

	// Connect to the destination (via upstream or directly)
	var destConn net.Conn
	if upstream != "" {
		destConn, err = dialThroughSocks(upstream, destAddr)
	} else {
		// Direct connection: use the resolved IP address and port
		// Use net.JoinHostPort to correctly format the address
		addrStr := net.JoinHostPort(ipToUse, fmt.Sprint(port))
		log.Println("Dialing:", addrStr)
		destConn, err = net.Dial("tcp", addrStr)
	}
	if err != nil {
		writeReply(client, 0x05) // Connection refused
		fmt.Println("Connect failed:", err)
		return
	}
	defer destConn.Close()

	// Send success reply to client
	err = writeReply(client, 0x00)
	if err != nil {
		fmt.Println("Write reply failed:", err)
		return
	}

	// Relay data between client and destination
	go io.Copy(destConn, client)
	io.Copy(client, destConn)
}


// handleHandshake performs the SOCKS5 handshake
func handleHandshake(conn net.Conn) error {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n < 2 || buf[0] != 0x05 {
		return fmt.Errorf("invalid version")
	}
	methods := buf[2 : 2+buf[1]]
	if !bytes.Contains(methods, []byte{0x00}) {
		return fmt.Errorf("no supported auth method")
	}
	_, err = conn.Write([]byte{0x05, 0x00}) // Version 5, no auth
	return err
}

// readAddr parses the destination address from the client's request
func readAddr(conn net.Conn) (Addr, error) {
	header := make([]byte, 4)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return Addr{}, err
	}
	if header[0] != 0x05 || header[1] != 0x01 {
		return Addr{}, fmt.Errorf("invalid request")
	}
	atyp := header[3]
	var addr []byte
	switch atyp {
	case 0x01: // IPv4
		addr = make([]byte, 4)
		_, err = io.ReadFull(conn, addr)
	case 0x03: // Domain
		var lenByte [1]byte
		_, err = io.ReadFull(conn, lenByte[:])
		if err != nil {
			return Addr{}, err
		}
		domainLen := int(lenByte[0])
		addr = make([]byte, domainLen)
		_, err = io.ReadFull(conn, addr)
	case 0x04: // IPv6
		addr = make([]byte, 16)
		_, err = io.ReadFull(conn, addr)
	default:
		return Addr{}, fmt.Errorf("unsupported address type")
	}
	if err != nil {
		return Addr{}, err
	}
	portBuf := make([]byte, 2)
	_, err = io.ReadFull(conn, portBuf)
	if err != nil {
		return Addr{}, err
	}
	port := binary.BigEndian.Uint16(portBuf)
	return Addr{Atyp: atyp, Addr: addr, Port: port}, nil
}

// dialThroughSocks connects to a destination through an upstream SOCKS5 proxy
func dialThroughSocks(upstream string, dest Addr) (net.Conn, error) {
	conn, err := net.Dial("tcp", upstream)
	if err != nil {
		return nil, err
	}
	// Send handshake
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("upstream auth failed")
	}
	// Send request
	req := []byte{0x05, 0x01, 0x00, dest.Atyp}
	req = append(req, dest.Addr...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, dest.Port)
	req = append(req, portBytes...)
	_, err = conn.Write(req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Read reply
	reply := make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("upstream request failed: %d", reply[1])
	}
	// Skip the rest of the reply (bound address and port)
	atyp := reply[3]
	var addrLen int
	switch atyp {
	case 0x01:
		addrLen = 4
	case 0x03:
		var lenByte [1]byte
		_, err = io.ReadFull(conn, lenByte[:])
		if err != nil {
			conn.Close()
			return nil, err
		}
		addrLen = int(lenByte[0])
	case 0x04:
		addrLen = 16
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported address type in reply")
	}
	addrBuf := make([]byte, addrLen+2) // Address + 2-byte port
	_, err = io.ReadFull(conn, addrBuf)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// writeReply sends a SOCKS5 reply to the client
func writeReply(conn net.Conn, rep byte) error {
	buf := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0} // 0.0.0.0:0
	_, err := conn.Write(buf)
	return err
}