package sniff

import "FlowDetection/flowFeature"

type queueType = *flowFeature.TCPBaseFeature

type Queue struct {
	list []queueType
	Size int
}

func NewQueue() *Queue {
	return &Queue{
		list: make([]queueType, 0),
		Size: 0,
	}
}

func (q Queue) List() []queueType {
	return q.list
}

func (q *Queue) Front() queueType {
	if q.Size <= 0 {
		return nil
	}

	num := q.list[0]
	return num
}

func (q *Queue) Push(data queueType) {
	q.list = append(q.list, data)
	q.Size += 1
}

func (q *Queue) Pop() bool {
	if q.Size <= 0 {
		return false
	}

	q.Size--

	q.list = q.list[1:]
	return true
}
