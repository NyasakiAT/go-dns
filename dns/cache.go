package dns

import (
	"fmt"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/rs/zerolog/log"
)

type CacheEntry struct {
	RawPkt []byte
	Expiry  time.Time
}

func CacheRetrieve(q DNSQuestionPacket, cache *ristretto.Cache[string, CacheEntry]) (answers []byte) {
	key := fmt.Sprintf("%s|%d|%d", strings.ToLower(q.Question.Name), q.Question.Type, q.Question.Class)
	if v, found := cache.Get(key); found {
		entry := v
		if time.Now().Before(entry.Expiry) {
			return entry.RawPkt
		}
	}

	return nil
}

/* func CachePut(q DNSQuestionPacket, a DNSAnswerPacket, cache *ristretto.Cache[string, CacheEntry]) {
	if len(a.Answers) < 1 {
		log.Error().Msg("Tried to add empty answers to cache")
		return
	}

	key := fmt.Sprintf("%s|%d|%d", strings.ToLower(q.Question.Name), q.Question.Type, q.Question.Class)

	ttl := time.Duration(a.Answers[0].TTL) * time.Second
	entry := CacheEntry{Records: a.Answers, Expiry: time.Now().Add(ttl)}
	cache.SetWithTTL(key, entry, 1, ttl)
} */

func CachePutKey(key string, a DNSAnswerPacket, cache *ristretto.Cache[string, CacheEntry]) {
	if len(a.Answers) == 0 {
		log.Error().Msg("Tried to add empty answers to cache")
		return
	}
	rawPkt, _ := BuildAnswerPacket(a)
	ttl := time.Duration(a.Answers[0].TTL) * time.Second
	entry := CacheEntry{RawPkt: rawPkt, Expiry: time.Now().Add(ttl)}
	cache.SetWithTTL(key, entry, 1, ttl)
}
