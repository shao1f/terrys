package pool

import "sync"

func NewBytesPool(n int) sync.Pool {
	return sync.Pool{
		New: func() interface{} {
			return make([]byte, n)
		},
	}
}

var BP10 = NewBytesPool(10)
var BP32 = NewBytesPool(32)
var BP2048 = NewBytesPool(2048)
