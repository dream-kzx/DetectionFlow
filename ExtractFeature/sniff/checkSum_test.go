package sniff

import (
	"fmt"
	"log"
	"testing"
	"time"
)

type notify struct {
	perChan chan int
	ticker  *time.Ticker
}

func NewNotify(ch chan int) *notify {
	return &notify{
		ch,
		nil,
	}
}

func (n *notify) goTest() {
	if n.ticker != nil {
		n.ticker.Stop()
	}

	n.ticker = time.NewTicker(time.Second * 3)
	n.perChan <- 111
}

type testChan struct {
	tChan chan int
	no    []*notify
}

func NewTest() *testChan {
	return &testChan{
		tChan: make(chan int, 1),
		no:    make([]*notify, 0),
	}
}

func (t *testChan) forChan() {
	n := NewNotify(t.tChan)
	t.no = append(t.no, n)
	log.Println("222")
	go n.goTest()
	time.Sleep(time.Second)
	for {
		select {
		case k := <-t.tChan:
			log.Println(k)
		}
	}
}

type Test1 struct {
	a int
	b int
}

func NewTest1(a, b int) *Test1 {
	return &Test1{
		a: a,
		b: b,
	}
}

func TestCheckSum(t *testing.T) {
	a := []int{1,2,3,4,5,6}

	b := make([]int,len(a))
	copy(b,a)
	fmt.Println(b)
}
