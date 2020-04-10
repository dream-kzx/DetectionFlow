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

//对指定的值进行重置
//如果该值已存在在队列中，则先删除，然后加到队列尾部
func (q *KeyQueue) ResetValue(value uint64) {
	q.Lock()
	for i, v := range q.list {
		if v == value {
			q.list = removeSlice(q.list, i)
			break
		}
	}

	q.list = append(q.list, value)
	q.Unlock()
}

func (q *KeyQueue) RemoveValue(value uint64) {
	q.Lock()
	for i, v := range q.list {
		if v == value {
			q.Size--
			q.list = removeSlice(q.list, i)
			break
		}
	}
	q.Unlock()
}

func removeSlice(list []uint64, index int) []uint64 {
	return append(list[:index], list[index+1:]...)
}
