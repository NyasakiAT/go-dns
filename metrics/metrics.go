// metrics/metrics.go
package metrics

import "sync/atomic"

type Stats struct {
    CacheHits    atomic.Uint64
    CacheMisses  atomic.Uint64
    UpstreamOK   atomic.Uint64
    UpstreamErr  atomic.Uint64
}

func (s *Stats) Snapshot() map[string]uint64 {
    return map[string]uint64{
        "cache_hits":   s.CacheHits.Load(),
        "cache_misses": s.CacheMisses.Load(),
        "up_ok":        s.UpstreamOK.Load(),
        "up_err":       s.UpstreamErr.Load(),
    }
}
