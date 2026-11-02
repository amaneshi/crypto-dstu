package kupyna

import (
	"fmt"
	"testing"
)

var benchmarkSum []byte

func BenchmarkKupyna256(b *testing.B) {
	for _, size := range []int{64, 4096, 1 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i)
			}
			h := New256()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				h.Reset()
				h.Write(data)
				benchmarkSum = h.Sum(benchmarkSum[:0])
			}
		})
	}
}
