package sniff

import (
	// "log"
	"sync"
)

type KeyQueue struct {
	list []uint64
	Size int
	sync.Mutex
}

func NewKeyQueue() *KeyQueue {
	return &KeyQueue{
		list: make([]uint64, 0),
		Size: 0,
	}
}

func (q KeyQueue) List() []uint64 {
	return q.list
}

func (q *KeyQueue) Front() uint64 {
	if q.Size <= 0 {
		return 0
	}

	num := q.list[0]
	return num
}

func (q *KeyQueue) Push(data uint64) {
	q.list = append(q.list, data)
	q.Size += 1
}

func (q *KeyQueue) Pop() bool {
	if q.Size <= 0 {
		return false
	}

	q.Size--
	q.list = q.list[1:]
	return true
}

func (q *KeyQueue) ResetValue(value uint64){
	// log.Println("lock in rest")
	q.Lock()
	for i, v := range q.list{
		if v == value{
			q.list = removeSclie(q.list,i)
			break
		}
	}

	q.list = append(q.list,value)
	q.Unlock()
	// log.Println("unlock in rest")
}

func (q *KeyQueue) RemoveValue(value uint64){
	// log.Println("lock in remove")
	q.Lock()
	for i, v := range q.list{
		if v == value{
			q.Size--
			q.list = removeSclie(q.list,i)
			break
		}
	}
	q.Unlock()
	// log.Println("unlock in remove")

}

func removeSclie(list []uint64, index int) []uint64{
	return append(list[:index],list[index+1:]...)
}