// vaydns-client is the client end of a DNS tunnel.
//
// Usage:
//
//	vaydns-client [-doh URL|-dot ADDR|-tcp ADDR|-udp ADDR] [-pubkey HEX|-pubkey-file FILENAME] -domain DOMAIN -listen LOCALADDR
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/phoenixdnsvpn/phoenixdns/client"
	"github.com/phoenixdnsvpn/phoenixdns/dns"
	"github.com/phoenixdnsvpn/phoenixdns/noise"
	"github.com/phoenixdnsvpn/phoenixdns/turbotunnel"
	log "github.com/sirupsen/logrus"
)

var version = "dev"

func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// roundRobinTCPRelay distributes incoming TCP streams evenly across multiple active backend tunnels
func roundRobinTCPRelay(listenAddr string, backendPorts []int) error {
	localAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %v", err)
	}
	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", listenAddr, err)
	}
	defer ln.Close()

	log.Infof("[Multipath] Load Balancer active on %s, distributing across %d VayDNS tunnels", listenAddr, len(backendPorts))

	var counter uint64
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Warnf("Load balancer accept error: %v", err)
			continue
		}

		idx := atomic.AddUint64(&counter, 1) % uint64(len(backendPorts))
		target := fmt.Sprintf("127.0.0.1:%d", backendPorts[idx])

		go func(c net.Conn, backend string) {
			defer c.Close()
			remoteConn, err := net.Dial("tcp", backend)
			if err != nil {
				log.Warnf("Load Balancer dropped stream: Backend %s unreachable: %v", backend, err)
				return
			}
			defer remoteConn.Close()

			done := make(chan struct{}, 2)
			go func() {
				io.Copy(remoteConn, c)
				done <- struct{}{}
			}()
			go func() {
				io.Copy(c, remoteConn)
				done <- struct{}{}
			}()
			<-done
			<-done
		}(clientConn, target)
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())

	var showVersion bool
	var dohURL string
	var dotAddr string
	var tcpAddr string
	var domainArg string
	var listenAddr string
	var pubkeyFilename string
	var pubkeyString string
	var udpAddr string
	var utlsDistribution string
	var maxQnameLen int
	var maxNumLabels int
	var rpsLimit float64
	var idleTimeoutStr string
	var keepAliveStr string
	var reconnectMinStr string
	var reconnectMaxStr string
	var sessionCheckIntervalStr string
	var openStreamTimeoutStr string
	var maxStreams int
	var udpWorkers int
	var udpSharedSocket bool
	var udpTimeoutStr string
	var udpAcceptErrors bool
	var compatDnstt bool
	var clientIDSize int
	var recordTypeStr string
	var queueSize int
	var kcpWindowSize int
	var queueOverflowStr string
	var uploadMinMTU int
	var uploadMaxMTU int
	var downloadMinMTU int
	var downloadMaxMTU int

	// --- NEW FLAGS ---
	var disableDynamicMTU bool
	var fixedMTU int
	var mtuDiscoveryRetries int
	var multiResolverCount int

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-doh URL|-dot ADDR|-tcp ADDR|-udp ADDR] -pubkey-file PUBKEYFILE -domain DOMAIN -listen LOCALADDR  

Examples:
  %[1]s -doh https://resolver.example/dns-query -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
  %[1]s -udp 8.8.8.8:53,8.8.4.4:53,208.67.222.222:53 -use-multi-resolver 3 -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
  %[1]s -tcp resolver.example:53 -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000  

`, os.Args[0])
		flag.CommandLine.VisitAll(func(f *flag.Flag) {
			if f.Name == "session-check-interval" {
				return
			}
			fmt.Fprintf(flag.CommandLine.Output(), "  -%s", f.Name)
			name, usage := flag.UnquoteUsage(f)
			if len(name) > 0 {
				fmt.Fprintf(flag.CommandLine.Output(), " %s", name)
			}
			if len(f.DefValue) > 0 {
				fmt.Fprintf(flag.CommandLine.Output(), " (default %s)", f.DefValue)
			}
			if len(usage) > 0 {
				fmt.Fprintf(flag.CommandLine.Output(), "\n    \t%s", usage)
			}
			fmt.Fprint(flag.CommandLine.Output(), "\n")
		})
		labels := make([]string, 0)
		labels = append(labels, "none")
		for _, entry := range client.UTLSClientHelloIDMap() {
			labels = append(labels, entry.Label)
		}
		fmt.Fprintf(flag.CommandLine.Output(), `
Known TLS fingerprints for -utls are:
`)
		i := 0
		for i < len(labels) {
			var line strings.Builder
			fmt.Fprintf(&line, "  %s", labels[i])
			w := 2 + len(labels[i])
			i++
			for i < len(labels) && w+1+len(labels[i]) <= 72 {
				fmt.Fprintf(&line, " %s", labels[i])
				w += 1 + len(labels[i])
				i++
			}
			fmt.Fprintln(flag.CommandLine.Output(), line.String())
		}
	}
	flag.StringVar(&dohURL, "doh", "", "URL of DoH resolver (comma-separated for multi-resolver)")
	flag.StringVar(&dotAddr, "dot", "", "address of DoT resolver (comma-separated for multi-resolver)")
	flag.StringVar(&tcpAddr, "tcp", "", "address of TCP DNS resolver (comma-separated for multi-resolver)")	
	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "read server public key from file")
	flag.StringVar(&udpAddr, "udp", "", "address of UDP DNS resolver (comma-separated for multi-resolver)")
	flag.IntVar(&multiResolverCount, "use-multi-resolver", 3, "number of resolvers to use for multi-path load balancing (1-4, default 3; 1 uses single/racing logic)")
	flag.StringVar(&utlsDistribution, "utls",
		"4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13",
		"choose TLS fingerprint from weighted distribution")
	flag.StringVar(&domainArg, "domain", "", "tunnel domain (e.g., t.example.com)")
	flag.StringVar(&listenAddr, "listen", "", "TCP address to listen on for local connections (e.g., 127.0.0.1:7000)")
	flag.IntVar(&maxQnameLen, "max-qname-len", 253, "maximum total QNAME length in wire format (0 = 253 per RFC 1035)")
	flag.IntVar(&maxNumLabels, "max-num-labels", 0, "maximum number of data labels in query name (0 = unlimited)")
	flag.Float64Var(&rpsLimit, "rps", 0, "limit outgoing DNS queries per second (0 = unlimited)")
	flag.StringVar(&idleTimeoutStr, "idle-timeout", client.DefaultIdleTimeout.String(), "session idle timeout (e.g. 10s, 1m); reconnects if no data received within this period")
	flag.StringVar(&keepAliveStr, "keepalive", client.DefaultKeepAlive.String(), "keepalive ping interval (e.g. 2s, 500ms); must be less than idle-timeout")
	flag.StringVar(&reconnectMinStr, "reconnect-min", client.DefaultReconnectDelay.String(), "minimum delay before retrying session creation (e.g. 500ms, 1s)")
	flag.StringVar(&reconnectMaxStr, "reconnect-max", client.DefaultReconnectMaxDelay.String(), "maximum delay before retrying session creation (e.g. 5s, 30s)")
	flag.StringVar(&sessionCheckIntervalStr, "session-check-interval", client.DefaultSessionCheckInterval.String(), "interval for checking whether the current session is still alive (e.g. 100ms, 500ms)")
	flag.StringVar(&openStreamTimeoutStr, "open-stream-timeout", client.DefaultOpenStreamTimeout.String(), "timeout for opening a multiplexed stream (e.g. 500ms, 3s)")
	flag.IntVar(&maxStreams, "max-streams", client.DefaultMaxStreams, "max concurrent streams per session (0 = unlimited)")
	flag.IntVar(&udpWorkers, "udp-workers", client.DefaultUDPWorkers, "number of concurrent UDP worker goroutines")
	flag.BoolVar(&udpSharedSocket, "udp-shared-socket", false, "use a single shared UDP socket instead of per-query sockets")
	flag.StringVar(&udpTimeoutStr, "udp-timeout", client.DefaultUDPResponseTimeout.String(), "per-query UDP response timeout (e.g. 200ms, 1s)")
	flag.BoolVar(&udpAcceptErrors, "udp-accept-errors", false, "accept DNS error responses instead of filtering them (disables censorship evasion)")
	flag.BoolVar(&compatDnstt, "dnstt-compat", false, "use original dnstt wire format (8-byte ClientID, padding prefixes)")
	flag.IntVar(&clientIDSize, "clientid-size", 2, "client ID size in bytes (ignored when -dnstt-compat is set)")
	flag.StringVar(&recordTypeStr, "record-type", "txt", "DNS record type for downstream data (txt, null, cname, a, aaaa, mx, ns, srv, caa)")
	flag.IntVar(&queueSize, "queue-size", turbotunnel.QueueSize, "packet queue size for transport and DNS layers")
	flag.IntVar(&kcpWindowSize, "kcp-window-size", 0, "KCP send/receive window size in packets (0 = queue-size/2)")
	flag.StringVar(&queueOverflowStr, "queue-overflow", string(turbotunnel.DefaultQueueOverflowMode), "queue overflow behavior: drop or block")
	flag.IntVar(&uploadMinMTU, "upload-min-mtu", 40, "minimum upload MTU to probe")
	flag.IntVar(&uploadMaxMTU, "upload-max-mtu", 140, "maximum upload MTU to probe")
	flag.IntVar(&downloadMinMTU, "download-min-mtu", 200, "minimum download MTU to probe")
	flag.IntVar(&downloadMaxMTU, "download-max-mtu", 1232, "maximum download MTU to probe")
	
	// --- NEW FLAGS MAP ---
	flag.BoolVar(&disableDynamicMTU, "disable-mtu-discovery", false, "disable dynamic MTU discovery and use static calculation")
	flag.IntVar(&fixedMTU, "mtu", 0, "force a specific upload MTU (requires -disable-mtu-discovery)")
	flag.IntVar(&mtuDiscoveryRetries, "mtu-discovery-retries", 1, "number of retries for MTU discovery probes (0-3)")

	var logLevel string
	flag.StringVar(&logLevel, "log-level", "info", "log level (debug, info, warning, error)")
	flag.BoolVar(&showVersion, "v", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if multiResolverCount < 1 || multiResolverCount > 4 {
		fmt.Fprintf(os.Stderr, "-use-multi-resolver must be between 1 and 4 (inclusive)\n")
		os.Exit(1)
	}

	level, err := log.ParseLevel(logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level: %s\n", logLevel)
		os.Exit(1)
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05"})

	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected positional arguments\n")
		flag.Usage()
		os.Exit(1)
	}
	if domainArg == "" {
		fmt.Fprintf(os.Stderr, "the -domain option is required\n")
		os.Exit(1)
	}
	if listenAddr == "" {
		fmt.Fprintf(os.Stderr, "the -listen option is required\n")
		os.Exit(1)
	}
	log.Infof("using domain: %s", domainArg)

	if _, err := dns.ParseRecordType(recordTypeStr); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	recordTypeStr = strings.ToLower(recordTypeStr)
	log.Infof("record type: %s", recordTypeStr)

	// Resolve public key.
	var pubkeyHex string
	if pubkeyFilename != "" && pubkeyString != "" {
		fmt.Fprintf(os.Stderr, "only one of -pubkey and -pubkey-file may be used\n")
		os.Exit(1)
	} else if pubkeyFilename != "" {
		pubkey, err := readKeyFromFile(pubkeyFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read pubkey from file: %v\n", err)
			os.Exit(1)
		}
		pubkeyHex = hex.EncodeToString(pubkey)
	} else if pubkeyString != "" {
		pubkeyHex = pubkeyString
	}
	if pubkeyHex == "" {
		fmt.Fprintf(os.Stderr, "the -pubkey or -pubkey-file option is required\n")
		os.Exit(1)
	}

	// Select uTLS fingerprint.
	utlsClientHelloID, err := client.SampleUTLSDistribution(utlsDistribution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}
	if utlsClientHelloID != nil {
		log.Infof("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	// Select resolver transport.
	var resolverType client.ResolverType
	var resolverAddr string
	transportCount := 0
	if dohURL != "" {
		resolverType = client.ResolverTypeDOH
		resolverAddr = dohURL
		transportCount++
	}
	if dotAddr != "" {
		resolverType = client.ResolverTypeDOT
		resolverAddr = dotAddr
		transportCount++
	}
	if tcpAddr != "" {
		resolverType = client.ResolverTypeTCP
		resolverAddr = tcpAddr
		transportCount++
	}	
	if udpAddr != "" {
		resolverType = client.ResolverTypeUDP
		resolverAddr = udpAddr
		transportCount++
	}
	if transportCount == 0 {
		fmt.Fprintf(os.Stderr, "one of -doh, -dot, -tcp, or -udp is required\n")
		os.Exit(1)
	}
	if transportCount > 1 {
		fmt.Fprintf(os.Stderr, "only one of -doh, -dot, -tcp, and -udp may be given\n")
		os.Exit(1)
	}

	// Parse durations.
	idleTimeout, err := time.ParseDuration(idleTimeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -idle-timeout: %v\n", err)
		os.Exit(1)
	}
	keepAlive, err := time.ParseDuration(keepAliveStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -keepalive: %v\n", err)
		os.Exit(1)
	}
	reconnectMinDelay, err := time.ParseDuration(reconnectMinStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -reconnect-min: %v\n", err)
		os.Exit(1)
	}
	reconnectMaxDelay, err := time.ParseDuration(reconnectMaxStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -reconnect-max: %v\n", err)
		os.Exit(1)
	}
	sessionCheckInterval, err := time.ParseDuration(sessionCheckIntervalStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -session-check-interval: %v\n", err)
		os.Exit(1)
	}
	openStreamTimeout, err := time.ParseDuration(openStreamTimeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -open-stream-timeout: %v\n", err)
		os.Exit(1)
	}
	udpTimeout, err := time.ParseDuration(udpTimeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -udp-timeout: %v\n", err)
		os.Exit(1)
	}

	// Validate.
	if keepAlive >= idleTimeout {
		fmt.Fprintf(os.Stderr, "-keepalive (%s) must be less than -idle-timeout (%s)\n", keepAlive, idleTimeout)
		os.Exit(1)
	}
	if reconnectMinDelay <= 0 {
		fmt.Fprintf(os.Stderr, "-reconnect-min (%s) must be greater than 0\n", reconnectMinDelay)
		os.Exit(1)
	}
	if reconnectMaxDelay < reconnectMinDelay {
		fmt.Fprintf(os.Stderr, "-reconnect-max (%s) must be greater than or equal to -reconnect-min (%s)\n", reconnectMaxDelay, reconnectMinDelay)
		os.Exit(1)
	}
	if sessionCheckInterval <= 0 {
		fmt.Fprintf(os.Stderr, "-session-check-interval (%s) must be greater than 0\n", sessionCheckInterval)
		os.Exit(1)
	}
	if openStreamTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "-open-stream-timeout (%s) must be greater than 0\n", openStreamTimeout)
		os.Exit(1)
	}
	if queueSize <= 0 {
		fmt.Fprintf(os.Stderr, "-queue-size (%d) must be greater than 0\n", queueSize)
		os.Exit(1)
	}
	if kcpWindowSize < 0 {
		fmt.Fprintf(os.Stderr, "-kcp-window-size (%d) must be >= 0\n", kcpWindowSize)
		os.Exit(1)
	}
	if kcpWindowSize == 0 {
		kcpWindowSize = queueSize / 2
		if kcpWindowSize < 1 {
			kcpWindowSize = 1
		}
	}
	if kcpWindowSize > queueSize {
		fmt.Fprintf(os.Stderr, "-kcp-window-size (%d) must be <= -queue-size (%d)\n", kcpWindowSize, queueSize)
		os.Exit(1)
	}
	queueOverflowMode, err := turbotunnel.ParseQueueOverflowMode(queueOverflowStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -queue-overflow: %v\n", err)
		os.Exit(1)
	}

	if uploadMinMTU <= 0 || uploadMaxMTU <= 0 || downloadMinMTU <= 0 || downloadMaxMTU <= 0 {
		fmt.Fprintf(os.Stderr, "MTU values must be positive\n")
		os.Exit(1)
	}
	if uploadMinMTU > uploadMaxMTU {
		fmt.Fprintf(os.Stderr, "-upload-min-mtu (%d) cannot be greater than -upload-max-mtu (%d)\n", uploadMinMTU, uploadMaxMTU)
		os.Exit(1)
	}
	if downloadMinMTU > downloadMaxMTU {
		fmt.Fprintf(os.Stderr, "-download-min-mtu (%d) cannot be greater than -download-max-mtu (%d)\n", downloadMinMTU, downloadMaxMTU)
		os.Exit(1)
	}
	
	if mtuDiscoveryRetries < 0 || mtuDiscoveryRetries > 3 {
		fmt.Fprintf(os.Stderr, "-mtu-discovery-retries must be between 0 and 3\n")
		os.Exit(1)
	}
		
	// Apply -dnstt-compat overrides.
	if compatDnstt {
		if recordTypeStr != "txt" {
			log.Warnf("-dnstt-compat forces record-type to txt; ignoring -record-type %s", recordTypeStr)
			recordTypeStr = "txt"
		}
		explicitFlags := make(map[string]bool)
		flag.Visit(func(f *flag.Flag) {
			explicitFlags[f.Name] = true
		})
		if !explicitFlags["max-qname-len"] {
			maxQnameLen = 253
		}
		if !explicitFlags["idle-timeout"] {
			idleTimeout = client.DnsttIdleTimeout
		}
		if !explicitFlags["keepalive"] {
			keepAlive = client.DnsttKeepAlive
		}
		if keepAlive >= idleTimeout {
			fmt.Fprintf(os.Stderr, "-keepalive (%s) must be less than -idle-timeout (%s)\n", keepAlive, idleTimeout)
			os.Exit(1)
		}
		
		if !explicitFlags["download-max-mtu"] {
			if resolverType == client.ResolverTypeTCP || resolverType == client.ResolverTypeDOT || resolverType == client.ResolverTypeDOH {
				downloadMaxMTU = 1232
			}
		}		
	}

	// Build base tunnel server config.
	ts, err := client.NewTunnelServer(domainArg, pubkeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	ts.DnsttCompat = compatDnstt
	ts.ClientIDSize = clientIDSize
	ts.MaxQnameLen = maxQnameLen
	ts.MaxNumLabels = maxNumLabels
	ts.RPS = rpsLimit
	ts.RecordType = recordTypeStr
	ts.UploadMinMTU = uploadMinMTU
	ts.UploadMaxMTU = uploadMaxMTU
	ts.DownloadMinMTU = downloadMinMTU
	ts.DownloadMaxMTU = downloadMaxMTU
	ts.DisableDynamicMTU = disableDynamicMTU
	ts.MTU = fixedMTU
	ts.MTUDiscoveryRetries = mtuDiscoveryRetries

	if compatDnstt {
		log.Infof("wire config: clientid-size=8 compat=true")
	} else {
		log.Infof("wire config: clientid-size=%d compat=false", clientIDSize)
	}

	if rpsLimit > 0 {
		log.Infof("rate limiting DNS queries to %.1f requests per second", rpsLimit)
	}

	// Helper function to build a configured Tunnel instance for a given resolver address
	createTunnelInstance := func(targetAddr string) (*client.Tunnel, error) {
		r, err := client.NewResolver(resolverType, targetAddr)
		if err != nil {
			return nil, fmt.Errorf("resolver creation error: %w", err)
		}
		r.UTLSClientHelloID = utlsClientHelloID
		r.UDPWorkers = udpWorkers
		r.UDPSharedSocket = udpSharedSocket
		r.UDPTimeout = udpTimeout
		r.UDPAcceptErrors = udpAcceptErrors

		t, err := client.NewTunnel(r, ts)
		if err != nil {
			return nil, fmt.Errorf("tunnel creation error: %w", err)
		}
		t.IdleTimeout = idleTimeout
		t.KeepAlive = keepAlive
		t.OpenStreamTimeout = openStreamTimeout
		t.MaxStreams = maxStreams
		t.ReconnectMinDelay = reconnectMinDelay
		t.ReconnectMaxDelay = reconnectMaxDelay
		t.SessionCheckInterval = sessionCheckInterval
		t.PacketQueueSize = queueSize
		t.KCPWindowSize = kcpWindowSize
		t.QueueOverflowMode = queueOverflowMode
		return t, nil
	}

	// Parse comma-separated resolvers
	rawResolvers := strings.Split(resolverAddr, ",")
	var cleanResolvers []string
	for _, r := range rawResolvers {
		r = strings.TrimSpace(r)
		if r != "" {
			cleanResolvers = append(cleanResolvers, r)
		}
	}
	if len(cleanResolvers) == 0 {
		fmt.Fprintf(os.Stderr, "no valid resolver addresses specified\n")
		os.Exit(1)
	}

	// =========================================================================
	// PATH A: RACING / SINGLE RESOLVER (N == 1 or only 1 resolver specified)
	// =========================================================================
	if multiResolverCount == 1 || len(cleanResolvers) <= 1 {
		log.Infof("[Tunnel] Spawning single tunnel engine (Racing/Single mode)")
		// Pass the raw resolverAddr (which can be comma-separated for internal racing)
		tunnel, err := createTunnelInstance(resolverAddr)
		if err != nil {
			log.Fatalf("%v", err)
		}
		log.Infof("transport config: queue-size=%d kcp-window-size=%d queue-overflow=%s", queueSize, kcpWindowSize, queueOverflowMode)
		if err := tunnel.ListenAndServe(listenAddr); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	// =========================================================================
	// PATH B: MULTIPATH LOAD BALANCER (N > 1 with multiple resolvers)
	// =========================================================================
	selectedResolvers := cleanResolvers
	if len(selectedResolvers) > multiResolverCount {
		selectedResolvers = selectedResolvers[:multiResolverCount]
	}

	var backendPorts []int
	usedPorts := make(map[int]bool)

	for _, singleAddr := range selectedResolvers {
		var bgPort int
		for {
			bgPort = 40000 + rand.Intn(10000)
			if !usedPorts[bgPort] {
				usedPorts[bgPort] = true
				break
			}
		}
		backendPorts = append(backendPorts, bgPort)

		bgTunnel, err := createTunnelInstance(singleAddr)
		if err != nil {
			log.Fatalf("failed to create tunnel for %s: %v", singleAddr, err)
		}

		go func(t *client.Tunnel, addr string, port int) {
			log.Infof("[Multipath] Booting dedicated tunnel path for %s on port 127.0.0.1:%d", addr, port)
			if err := t.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
				log.Warnf("Tunnel path %s on port %d exited: %v", addr, port, err)
			}
		}(bgTunnel, singleAddr, bgPort)
	}

	if err := roundRobinTCPRelay(listenAddr, backendPorts); err != nil {
		log.Fatalf("Load balancer relay error: %v", err)
	}
}
