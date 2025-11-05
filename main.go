package main

import (
	"encoding/json"
	"net/http"

	"nyasaki/dns-server/dns"
	"nyasaki/dns-server/metrics"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	stats := &metrics.Stats{}

	go func() {
        http.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
            json.NewEncoder(w).Encode(map[string]uint64{
                "cache_hits":   stats.CacheHits.Load(),
                "cache_misses": stats.CacheMisses.Load(),
                "up_ok":        stats.UpstreamOK.Load(),
                "up_err":       stats.UpstreamErr.Load(),
                "serve_stale":  stats.ServeStale.Load(),
            })
        })
        _ = http.ListenAndServe(":8081", nil)
    }()

	log.Info().Msg("Starting DNS")
	dns.StartServer(stats)
}
