package main

// §13.4's SNI split in the lb's nginx render (W1, D-TLS-2, R-TLS-1): rendered
// only when the latest version's lb block has a tls_split, so without one the
// render is byte for byte what it was before the split existed.
//
// The stream block gains one server on TCP 443 for both families. It reads
// the ClientHello's SNI with ssl_preread and maps it: each root and the
// platform names the http servers serve under it go to lb-https, the http
// servers' unix socket; every other name under a root, `*.<root>`, goes to
// the tls edge's 443 stream; the custom-host include adds lbmap's hosts
// (TLS-M6-01); anything else, and a hello without SNI, goes to lb-https.
// Exact names win, then the longest wildcard, so a platform name left under a
// root keeps working until §12.4's move. Both branches get PROXY v1.
//
// The http block's 443 listens move to the unix socket, with proxy_protocol,
// and realip restores the visitor's address from PROXY, so per-address zones
// and X-UR-Forwarded-For see the visitor and not the socket. H3 keeps UDP 443
// (D-TLS-10), so `listen 443 quic` stays. Port 80 gains a redirect for the
// roots' names that logs nothing (I-13), and the custom hosts' include.
//
// A platform name under a root must be one of §12.5's reserved labels, or a
// network could take its label and its names would route to that network's
// listener: the render refuses one that is not. warp cannot import sidecar,
// so dns_reserved_labels.txt is a copy of sidecar's, which a test holds
// byte-equal to the sibling file.

import (
	_ "embed"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"golang.org/x/exp/maps"

	"github.com/urnetwork/warp"
	"github.com/urnetwork/warp/services"
)

//go:embed dns_reserved_labels.txt
var tlsSplitReservedLabelsText string

// The upstream of the split's default branch: the http servers' socket.
const tlsSplitHttpsUpstream = "lb-https"

// Each visitor connection on 443 holds up to this many worker connections
// behind the split: the stream server's accepted one, its connection to the
// socket, and the http server's end of that, where it held one before.
const tlsSplitWorkerConnectionsPerVisitor = 3

// A map key may be a custom host of up to 253 bytes (RFC 1035 §2.3.4), which
// lbmap adds, and nginx refuses a map whose longest key outgrows its bucket,
// so the stream block sizes the bucket for one.
const tlsSplitMapHashBucketSize = 512

// §12.5's reserved labels as dns_reserved_labels.txt writes them: exact
// labels, and patterns whose `*` is the first or last character.
type tlsSplitReservedLabels struct {
	exactLabels map[string]bool
	// "main-" for main-*
	prefixes []string
	// "-lb" for *-lb
	suffixes []string
}

// Parses the list's lines as sidecar's parser does: blank lines and those
// starting with # say nothing; anything else is a lowercase label or a pattern.
func parseTlsSplitReservedLabels(text string) (*tlsSplitReservedLabels, error) {
	reserved := &tlsSplitReservedLabels{exactLabels: map[string]bool{}}
	lowerLdh := func(text string) bool {
		for index := range len(text) {
			c := text[index]
			if !('a' <= c && c <= 'z') && !('0' <= c && c <= '9') && c != '-' {
				return false
			}
		}
		return text != ""
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case !strings.Contains(line, "*"):
			if !lowerLdh(line) || strings.HasPrefix(line, "-") || strings.HasSuffix(line, "-") {
				return nil, fmt.Errorf("dns_reserved_labels.txt: %q is not a lowercase label", line)
			}
			reserved.exactLabels[line] = true
		case strings.Count(line, "*") == 1 && strings.HasPrefix(line, "*") && lowerLdh(line[1:]):
			reserved.suffixes = append(reserved.suffixes, line[1:])
		case strings.Count(line, "*") == 1 && strings.HasSuffix(line, "*") && lowerLdh(line[:len(line)-1]):
			reserved.prefixes = append(reserved.prefixes, line[:len(line)-1])
		default:
			return nil, fmt.Errorf("dns_reserved_labels.txt: %q is neither a label nor a pattern", line)
		}
	}
	return reserved, nil
}

// Whether label, lowercase, is reserved, exactly or by a pattern.
func (self *tlsSplitReservedLabels) reserved(label string) bool {
	if self.exactLabels[label] {
		return true
	}
	for _, prefix := range self.prefixes {
		if strings.HasPrefix(label, prefix) && len(prefix) < len(label) {
			return true
		}
	}
	for _, suffix := range self.suffixes {
		if strings.HasSuffix(label, suffix) && len(suffix) < len(label) {
			return true
		}
	}
	return false
}

// The embedded list, parsed once. A copy that does not parse is a build
// mistake, which refuses every split render rather than guessing.
var tlsSplitReserved = sync.OnceValues(func() (*tlsSplitReservedLabels, error) {
	return parseTlsSplitReservedLabels(tlsSplitReservedLabelsText)
})

// The latest version's split, nil when there is none.
func (self *NginxConfig) tlsSplit() *services.TlsSplitConfig {
	lbConfig := self.servicesConfig.Versions[0].Lb
	if lbConfig == nil {
		return nil
	}
	return lbConfig.TlsSplit
}

// The stream upstream the split sends `*.<root>` to: the service's 443 stream.
func tlsSplitEdgeUpstream(split *services.TlsSplitConfig) string {
	return fmt.Sprintf("stream-service-block-%s-443", split.GetService())
}

// Every name the lb's http servers serve, from the whole services document,
// so every interface renders one map: the lb hosts, and each exposed http
// service's hosts and aliases. Lowercase, without a trailing dot, sorted and
// each once.
func (self *NginxConfig) tlsSplitHttpNames() []string {
	names := append([]string{}, self.lbHosts()...)
	serviceNames := maps.Keys(self.servicesConfig.Versions[0].Services)
	sort.Strings(serviceNames)
	for _, service := range serviceNames {
		serviceConfig := self.servicesConfig.Versions[0].Services[service]
		if serviceConfig.IsExposed() && slices.Contains(serviceConfig.HttpTcpPorts(), 80) {
			names = append(names, self.serviceHosts(service)...)
		}
	}
	for i, name := range names {
		names[i] = strings.TrimSuffix(strings.ToLower(name), ".")
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// The http names under root, the root itself left out, each checked: a name
// whose label under root is not reserved, or the root's own wildcard, refuses
// the render, since a network could hold that label (§12.5).
func (self *NginxConfig) tlsSplitPlatformNames(root string) ([]string, error) {
	reserved, err := tlsSplitReserved()
	if err != nil {
		return nil, err
	}
	platformNames := []string{}
	for _, name := range self.tlsSplitHttpNames() {
		below, under := strings.CutSuffix(name, "."+root)
		if !under {
			continue
		}
		labels := strings.Split(below, ".")
		label := labels[len(labels)-1]
		if label == "*" {
			return nil, fmt.Errorf("the lb serves %s, which would take every name the split sends under %s", name, root)
		}
		if !reserved.reserved(label) {
			return nil, fmt.Errorf("the lb serves %s under the split's root %s, but %q is not a reserved label (dns_reserved_labels.txt), so a network could hold it", name, root, label)
		}
		platformNames = append(platformNames, name)
	}
	return platformNames, nil
}

// Refuses a split this lb cannot render: a platform name that is not
// reserved, a proxy_buffer_size that does not parse.
func (self *NginxConfig) checkTlsSplit() error {
	split := self.tlsSplit()
	if split == nil {
		return nil
	}
	for _, root := range split.GetRoots() {
		if _, err := self.tlsSplitPlatformNames(root); err != nil {
			return err
		}
	}
	if _, err := split.GetProxyBufferByteCount(); err != nil {
		return fmt.Errorf("tls_split proxy_buffer_size: %w", err)
	}
	return nil
}

// Whether the stream upstream of service's port is the split's, which the
// split names though no tcp_stream_port_services entry does.
func (self *NginxConfig) tlsSplitUpstreamPort(service string, portType string, port int) bool {
	split := self.tlsSplit()
	return split != nil && service == split.GetService() && portType == "tcp" && port == 443
}

// The http servers' 443 listens: TCP 443 on both families, or behind the
// split the unix socket the stream server sends to with PROXY. first carries
// the options nginx takes once per address; reuseport has no meaning on a
// unix socket, so the socket's first listen carries only the backlog.
func (self *NginxConfig) addHttpsListens(first bool) {
	if self.tlsSplit() == nil {
		if first {
			self.raw(`
            listen 443 ssl reuseport backlog=65535;
            listen [::]:443 ssl reuseport backlog=65535;
            `)
		} else {
			self.raw(`
            listen 443 ssl;
            listen [::]:443 ssl;
            `)
		}
		return
	}
	if first {
		self.raw(`
        listen unix:{{.socket}} ssl proxy_protocol backlog=65535;
        `, map[string]any{
			"socket": warp.LbHttpsSocketPath,
		})
	} else {
		self.raw(`
        listen unix:{{.socket}} ssl proxy_protocol;
        `, map[string]any{
			"socket": warp.LbHttpsSocketPath,
		})
	}
}

// realip for the socket's connections: only the split's stream server reaches
// it, so its PROXY header carries the visitor's address and port, which
// $remote_addr, the per-address zones and X-UR-Forwarded-For then read.
func (self *NginxConfig) addTlsSplitRealIp() {
	if self.tlsSplit() == nil {
		return
	}
	self.raw(`
    # the tls split (W1): the http servers' 443 is a unix socket that only the
    # split's stream server reaches, so restore the visitor from its PROXY header
    set_real_ip_from unix:;
    real_ip_header proxy_protocol;
    `)
}

// Port 80 for the roots' names: a redirect to https that logs nothing, since
// a user's name is in the request (I-13), and lbmap's custom hosts beside it.
// Platform names keep their own servers, which an exact name wins.
func (self *NginxConfig) addTlsSplitHttp80() {
	split := self.tlsSplit()
	if split == nil || !slices.Contains(self.servicesConfig.Versions[0].Lb.HttpTcpPorts(), 80) {
		return
	}
	wildcards := []string{}
	for _, root := range split.GetRoots() {
		wildcards = append(wildcards, "*."+root)
	}
	self.block("server", func() {
		self.raw(`
        listen 80;
        listen [::]:80;
        server_name {{.wildcards}};
        access_log off;
        return 301 https://$host$request_uri;
        `, map[string]any{
			"wildcards": strings.Join(wildcards, " "),
		})
	})
	self.raw(`
    include {{.customHosts80}};
    `, map[string]any{
		"customHosts80": warp.LbTlsCustomHosts80Path,
	})
}

// The stream block's split: the map, the socket's upstream and the server on
// TCP 443. It writes no access log, as the stream block never has.
func (self *NginxConfig) addTlsSplitStream() {
	split := self.tlsSplit()
	if split == nil {
		return
	}
	edgeUpstream := tlsSplitEdgeUpstream(split)
	self.raw(`
    # the tls split (W1): names under a root, other than the root and the
    # platform names the http servers serve there, go unterminated to the tls
    # edge; everything else, and a hello without sni, to the http servers
    map_hash_bucket_size {{.bucketSize}};
    `, map[string]any{
		"bucketSize": tlsSplitMapHashBucketSize,
	})
	self.block("map $ssl_preread_server_name $tls_split_upstream", func() {
		self.raw(`
        hostnames;
        `)
		for _, root := range split.GetRoots() {
			// checkTlsSplit refused a render whose names do not check
			platformNames, err := self.tlsSplitPlatformNames(root)
			if err != nil {
				panic(err)
			}
			for _, name := range append([]string{root}, platformNames...) {
				self.raw(`
                {{.name}} {{.upstream}};
                `, map[string]any{
					"name":     name,
					"upstream": tlsSplitHttpsUpstream,
				})
			}
			self.raw(`
            *.{{.root}} {{.upstream}};
            `, map[string]any{
				"root":     root,
				"upstream": edgeUpstream,
			})
		}
		self.raw(`
        include {{.customHosts}};
        default {{.upstream}};
        `, map[string]any{
			"customHosts": warp.LbTlsCustomHostsMapPath,
			"upstream":    tlsSplitHttpsUpstream,
		})
	})
	self.block("upstream "+tlsSplitHttpsUpstream, func() {
		self.raw(`
        server unix:{{.socket}};
        `, map[string]any{
			"socket": warp.LbHttpsSocketPath,
		})
	})
	self.block("server", func() {
		self.raw(`
        listen 443 reuseport backlog=65535;
        listen [::]:443 reuseport backlog=65535;
        ssl_preread on;
        # tlsedge.yml's client_hello: the lb never passes a hello the edge refuses
        preread_timeout {{.timeoutSeconds}}s;
        preread_buffer_size {{.maxBytes}};
        proxy_protocol on;
        proxy_pass $tls_split_upstream;
        `, map[string]any{
			"timeoutSeconds": split.GetClientHelloTimeoutSeconds(),
			"maxBytes":       split.GetClientHelloMaxBytes(),
		})
		// checkTlsSplit refused one that does not parse
		proxyBufferByteCount, _ := split.GetProxyBufferByteCount()
		if 0 < proxyBufferByteCount {
			self.raw(`
            proxy_buffer_size {{.byteCount}};
            `, map[string]any{
				"byteCount": proxyBufferByteCount,
			})
		}
	})
}
