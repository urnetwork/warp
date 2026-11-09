//go:build linux || darwin

package splittest

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// TLS's record and handshake framing, which the edge stand-in reads to know
// where a ClientHello ends (RFC 8446 §5.1, §4).
const (
	tlsRecordHeaderByteCount    = 5
	tlsHandshakeHeaderByteCount = 4
	tlsContentTypeHandshake     = 0x16
	tlsContentTypeAlert         = 0x15
	tlsHandshakeTypeClientHello = 1
	// the most a stand-in reads of one hello, far past tlsedge's 16,384
	edgeHelloMaxByteCount = 64 * 1024
	// a PROXY v1 header's bound (the PROXY spec's 107 bytes)
	proxyV1MaxByteCount = 107
)

// What the edge stand-in received on one connection: PROXY v1's line, CRLF
// included, and the ClientHello's records exactly as sent.
type EdgeOpen struct {
	ProxyHeader string
	Hello       []byte
}

// Stands in for tlsedge behind the split: reads PROXY and the ClientHello,
// records them, answers unrecognized_name as tlsedge does for a name it does
// not know, and closes.
type EdgeBackend struct {
	listener net.Listener
	opens    chan *EdgeOpen

	stateLock sync.Mutex
	count     int
	errs      []error
}

// Listens on loopback and serves until Close.
func NewEdgeBackend() (*EdgeBackend, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	backend := &EdgeBackend{listener: listener, opens: make(chan *EdgeOpen, 1024)}
	go backend.run()
	return backend, nil
}

func (self *EdgeBackend) run() {
	for {
		conn, err := self.listener.Accept()
		if err != nil {
			return
		}
		go self.serve(conn)
	}
}

func (self *EdgeBackend) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, proxyV1MaxByteCount)
	open, err := readEdgeOpen(reader)
	self.stateLock.Lock()
	self.count += 1
	if err != nil {
		self.errs = append(self.errs, err)
	}
	self.stateLock.Unlock()
	if err != nil {
		return
	}
	self.opens <- open
	// unrecognized_name, fatal, as tlsedge answers an unknown name
	conn.Write([]byte{tlsContentTypeAlert, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70})
}

// Reads PROXY v1's line and then whole records until the ClientHello's
// handshake message is complete.
func readEdgeOpen(reader *bufio.Reader) (*EdgeOpen, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return nil, fmt.Errorf("proxy header: %w", err)
	}
	proxyHeader := string(line)
	hello := []byte{}
	handshake := []byte{}
	for {
		header := make([]byte, tlsRecordHeaderByteCount)
		if _, err := io.ReadFull(reader, header); err != nil {
			return nil, fmt.Errorf("record header: %w", err)
		}
		if header[0] != tlsContentTypeHandshake {
			return nil, fmt.Errorf("record type %d is not handshake", header[0])
		}
		length := int(header[3])<<8 | int(header[4])
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, fmt.Errorf("record: %w", err)
		}
		hello = append(append(hello, header...), payload...)
		handshake = append(handshake, payload...)
		if edgeHelloMaxByteCount < len(hello) {
			return nil, errors.New("hello past its bound")
		}
		if tlsHandshakeHeaderByteCount <= len(handshake) {
			if handshake[0] != tlsHandshakeTypeClientHello {
				return nil, fmt.Errorf("handshake type %d is not client hello", handshake[0])
			}
			messageLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if tlsHandshakeHeaderByteCount+messageLength <= len(handshake) {
				return &EdgeOpen{ProxyHeader: proxyHeader, Hello: hello}, nil
			}
		}
	}
}

// The stand-in's address, the split's `*.<root>` upstream.
func (self *EdgeBackend) Address() string {
	return self.listener.Addr().String()
}

// The next open received, or an error once timeout passes with none.
func (self *EdgeBackend) Next(timeout time.Duration) (*EdgeOpen, error) {
	select {
	case open := <-self.opens:
		return open, nil
	case <-time.After(timeout):
		return nil, errors.New("no open reached the edge")
	}
}

// How many connections reached the stand-in, and the errors of those that did
// not carry a PROXY header and a whole hello.
func (self *EdgeBackend) Count() (int, []error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.count, append([]error{}, self.errs...)
}

func (self *EdgeBackend) Close() error {
	return self.listener.Close()
}

// One request the http upstream saw.
type HttpRequest struct {
	Host              string
	Path              string
	UrForwardedFor    string
	ForwardedForCount int
}

// Stands in for the services behind the http servers: answers each request
// 200 with its path, records what reached it, and on /ws answers 101 and
// echoes what follows, as an upgraded connection carries it.
type HttpBackend struct {
	listener net.Listener
	server   *http.Server

	stateLock sync.Mutex
	requests  []*HttpRequest
}

// Listens on loopback and serves until Close.
func NewHttpBackend() (*HttpBackend, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	backend := &HttpBackend{listener: listener}
	backend.server = &http.Server{Handler: http.HandlerFunc(backend.handle)}
	go backend.server.Serve(listener)
	return backend, nil
}

func (self *HttpBackend) handle(writer http.ResponseWriter, request *http.Request) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, &HttpRequest{
			Host:              request.Host,
			Path:              request.URL.Path,
			UrForwardedFor:    request.Header.Get("X-UR-Forwarded-For"),
			ForwardedForCount: len(request.Header.Values("X-Forwarded-For")),
		})
	}()
	if request.URL.Path != "/ws" {
		writer.Header().Set("Content-Type", "text/plain")
		writer.Write([]byte(request.URL.Path))
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if err := buffered.Flush(); err != nil {
		return
	}
	io.Copy(conn, buffered)
}

// The upstream's address.
func (self *HttpBackend) Address() string {
	return self.listener.Addr().String()
}

// A copy of every request seen so far, oldest first.
func (self *HttpBackend) Requests() []*HttpRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	requests := []*HttpRequest{}
	for _, request := range self.requests {
		copied := *request
		requests = append(requests, &copied)
	}
	return requests
}

func (self *HttpBackend) Close() error {
	return self.server.Close()
}

// A ClientHello in one record whose SNI is serverName, padded with an
// extension of paddingByteCount zero bytes so a test can size it: what Go's
// crypto/tls will not write, a hello past a preread buffer.
func ClientHello(serverName string, paddingByteCount int) []byte {
	extension := func(extensionType uint16, body []byte) []byte {
		return append([]byte{byte(extensionType >> 8), byte(extensionType), byte(len(body) >> 8), byte(len(body))}, body...)
	}
	serverNameList := append([]byte{0x00, byte(len(serverName) >> 8), byte(len(serverName))}, serverName...)
	extensions := extension(0x0000, append([]byte{byte(len(serverNameList) >> 8), byte(len(serverNameList))}, serverNameList...))
	// supported_versions: TLS 1.3, so the hello is one a server would read
	extensions = append(extensions, extension(0x002b, []byte{0x02, 0x03, 0x04})...)
	extensions = append(extensions, extension(0x0015, make([]byte, paddingByteCount))...)
	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0x5a}, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	handshake := append([]byte{tlsHandshakeTypeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{tlsContentTypeHandshake, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}
