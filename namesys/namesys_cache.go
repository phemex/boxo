package namesys

import (
	"time"

	"github.com/ipfs/boxo/path"
)

type cacheEntry struct {
	val path.Path
	ttl time.Duration
	eol time.Time
}

func (ns *namesys) cacheGet(name string) (path.Path, time.Duration, bool) {
	// existence of optional mapping defined via IPFS_NS_MAP is checked first
	if ns.staticMap != nil {
		entry, ok := ns.staticMap[name]
		if ok {
			return entry.val, entry.ttl, true
		}
	}

	if ns.cache == nil {
		return nil, 0, false
	}

	entry, ok := ns.cache.Get(name)
	if !ok {
		return nil, 0, false
	}

	if time.Now().Before(entry.eol) {
		return entry.val, entry.ttl, true
	}

	ns.cache.Remove(name)
	return nil, 0, false
}

func (ns *namesys) cacheSet(name string, val path.Path, ttl time.Duration) {
	if ns.cache == nil || ttl <= 0 {
		return
	}

	ns.cache.Add(name, cacheEntry{
		val: val,
		ttl: ttl,
		eol: time.Now().Add(ttl),
	})
}

func (ns *namesys) cacheInvalidate(name string) {
	if ns.cache == nil {
		return
	}

	ns.cache.Remove(name)
}
