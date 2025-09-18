package warp

import (
	"net"
	"net/http"
	"time"
)

const DefaultHttpTimeout = 10 * time.Second
const DefaultHttpConnectTimeout = 5 * time.Second
const DefaultHttpTlsTimeout = 5 * time.Second

func DefaultHttpClient() *http.Client {
	// see https://medium.com/@nate510/don-t-use-go-s-default-http-client-4804cb19f779
	dialer := &net.Dialer{
		Timeout: DefaultHttpConnectTimeout,
	}
	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: DefaultHttpTlsTimeout,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   DefaultHttpTimeout,
	}
}
