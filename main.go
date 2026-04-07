package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	maskCols map[string]bool
	dbg      *log.Logger
)

func main() {
	listenAddr := getEnv("LISTEN_ADDR", ":20000")
	backendAddr := getEnv("BACKEND_ADDR", "")
	backendSSL := getEnv("BACKEND_SSL", "false") == "true"
	cols := getEnv("MASK_COLUMNS", "email")

	if backendAddr == "" {
		log.Fatal("BACKEND_ADDR is required (host:port)")
	}

	debugOut := io.Discard
	if getEnv("DEBUG", "false") == "true" {
		debugOut = os.Stderr
	}
	dbg = log.New(debugOut, "[debug] ", log.LstdFlags)

	maskCols = make(map[string]bool)
	for _, c := range strings.Split(cols, ",") {
		maskCols[strings.ToLower(strings.TrimSpace(c))] = true
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("pg-mask-proxy listening on %s -> %s (ssl=%v), masking columns: %s",
		listenAddr, backendAddr, backendSSL, cols)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn, backendAddr, backendSSL)
	}
}

func handleConn(client net.Conn, backendAddr string, useSSL bool) {
	defer func() { _ = client.Close() }()
	dbg.Printf("client connected: %s", client.RemoteAddr())

	startup, err := readClientStartup(client)
	if err != nil {
		return
	}

	dbg.Printf("dialing backend %s (ssl=%v)", backendAddr, useSSL)
	var backend net.Conn
	rawConn, err := net.DialTimeout("tcp", backendAddr, 10*time.Second)
	if err != nil {
		log.Printf("tcp dial failed: %v", err)
		return
	}
	dbg.Printf("tcp connected")
	if useSSL {
		// PostgreSQL SSL negotiation: send SSLRequest, expect 'S', then upgrade
		sslRequest := []byte{0, 0, 0, 8, 4, 210, 22, 47} // len=8, code=80877103
		if _, err = rawConn.Write(sslRequest); err != nil {
			log.Printf("ssl request write failed: %v", err)
			_ = rawConn.Close()
			return
		}
		resp := make([]byte, 1)
		if _, err = io.ReadFull(rawConn, resp); err != nil {
			log.Printf("ssl response read failed: %v", err)
			_ = rawConn.Close()
			return
		}
		dbg.Printf("ssl negotiation response: %c", resp[0])
		if resp[0] != 'S' {
			log.Printf("backend declined SSL: %c", resp[0])
			_ = rawConn.Close()
			return
		}
		host, _, _ := net.SplitHostPort(backendAddr)
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		dbg.Printf("starting TLS handshake")
		if err = tlsConn.Handshake(); err != nil {
			log.Printf("TLS handshake failed: %v", err)
			return
		}
		dbg.Printf("TLS handshake done")
		backend = tlsConn
	} else {
		backend = rawConn
	}
	defer func() { _ = backend.Close() }()

	dbg.Printf("forwarding startup (%d bytes)", len(startup))
	if _, err := backend.Write(startup); err != nil {
		log.Printf("failed to write startup: %v", err)
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(backend, client)
	}()

	var columns []string
	typeBuf := make([]byte, 1)
	lenBuf := make([]byte, 4)

	for {
		if _, err := io.ReadFull(backend, typeBuf); err != nil {
			break
		}
		msgType := typeBuf[0]

		if _, err := io.ReadFull(backend, lenBuf); err != nil {
			break
		}
		bodyLen := int(binary.BigEndian.Uint32(lenBuf)) - 4
		body := make([]byte, max(bodyLen, 0))
		if bodyLen > 0 {
			if _, err := io.ReadFull(backend, body); err != nil {
				break
			}
		}

		switch msgType {
		case 'T': // RowDescription — record column names
			columns = parseRowDescription(body)
			writeMsg(client, msgType, body)
		case 'D': // DataRow — mask configured columns
			writeMsg(client, msgType, maskDataRow(body, columns))
		case 'R': // Authentication — strip SCRAM-SHA-256-PLUS so plain clients can auth
			if len(body) >= 4 && binary.BigEndian.Uint32(body[0:4]) == 10 {
				body = stripSCRAMPlus(body)
			}
			writeMsg(client, msgType, body)
		default:
			writeMsg(client, msgType, body)
		}
	}

	<-done
}

// readClientStartup reads the startup message, transparently declining any
// GSSENCRequest (80877104) or SSLRequest (80877103) negotiation attempts.
func readClientStartup(client net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	for {
		if _, err := io.ReadFull(client, lenBuf); err != nil {
			return nil, err
		}
		msgLen := int(binary.BigEndian.Uint32(lenBuf))
		body := make([]byte, msgLen-4)
		if _, err := io.ReadFull(client, body); err != nil {
			return nil, err
		}

		if msgLen == 8 && len(body) == 4 {
			code := binary.BigEndian.Uint32(body)
			if code == 80877103 || code == 80877104 {
				// SSLRequest or GSSENCRequest — decline both
				dbg.Printf("declining negotiation code=%d", code)
				_, _ = client.Write([]byte{'N'})
				continue
			}
		}

		dbg.Printf("startup message received: len=%d", msgLen)
		msg := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(msg, uint32(msgLen))
		copy(msg[4:], body)
		return msg, nil
	}
}

// stripSCRAMPlus removes SCRAM-SHA-256-PLUS from an AuthenticationSASL body so
// clients connecting without TLS can fall back to plain SCRAM-SHA-256.
func stripSCRAMPlus(body []byte) []byte {
	result := make([]byte, 4, len(body))
	copy(result, body[0:4])
	i := 4
	for i < len(body) {
		end := i
		for end < len(body) && body[end] != 0 {
			end++
		}
		if i == end {
			result = append(result, 0)
			break
		}
		if string(body[i:end]) != "SCRAM-SHA-256-PLUS" {
			result = append(result, body[i:end+1]...)
		}
		i = end + 1
	}
	return result
}

func writeMsg(w io.Writer, msgType byte, body []byte) {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(body)+4))
	_, _ = w.Write([]byte{msgType})
	_, _ = w.Write(lenBuf)
	_, _ = w.Write(body)
}

// parseRowDescription extracts column names from a RowDescription message body.
// Format: int16(numFields) + per field: string(name\0) + int32 + int16 + int32 + int16 + int32 + int16
func parseRowDescription(body []byte) []string {
	if len(body) < 2 {
		return nil
	}
	numFields := int(binary.BigEndian.Uint16(body[0:2]))
	columns := make([]string, numFields)
	offset := 2
	for i := 0; i < numFields; i++ {
		end := offset
		for end < len(body) && body[end] != 0 {
			end++
		}
		columns[i] = string(body[offset:end])
		offset = end + 1 + 18 // null terminator + 18 bytes of field metadata
	}
	return columns
}

// maskDataRow rewrites a DataRow message body, replacing masked column values.
// Format: int16(numFields) + per field: int32(len) + bytes
func maskDataRow(body []byte, columns []string) []byte {
	if len(body) < 2 {
		return body
	}
	numFields := int(binary.BigEndian.Uint16(body[0:2]))
	result := []byte{body[0], body[1]}
	offset := 2

	for i := 0; i < numFields; i++ {
		if offset+4 > len(body) {
			break
		}
		colLen := int32(binary.BigEndian.Uint32(body[offset : offset+4]))

		if colLen == -1 {
			// NULL
			result = append(result, body[offset:offset+4]...)
			offset += 4
		} else if i < len(columns) && maskCols[strings.ToLower(columns[i])] {
			masked := []byte("****")
			newLen := make([]byte, 4)
			binary.BigEndian.PutUint32(newLen, uint32(len(masked)))
			result = append(result, newLen...)
			result = append(result, masked...)
			offset += 4 + int(colLen)
		} else {
			result = append(result, body[offset:offset+4+int(colLen)]...)
			offset += 4 + int(colLen)
		}
	}
	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
