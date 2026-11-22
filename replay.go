package krb5

import (
	"errors"
	"sync"
	"time"
)

// The replay cache (RFC 4120 §3.2.3) is this package's own, not gokrb5's
// service.Cache, which has three defects an acceptor cannot live with:
//
//   - it keys on the client name WITHOUT its realm, so alice@A and alice@B
//     presenting an authenticator in the same microsecond collide and the
//     second, genuine, one is refused;
//   - it checks and then adds in two separately locked steps, so concurrent
//     copies of one AP-REQ can all pass the check;
//   - it keeps one entry per authenticator with no bound, and any client
//     holding a valid ticket can mint authenticators (it knows the session key).
//
// This one decides in a single critical section, keys on realm, client,
// service and time, and is capped in total and per client; a full cache
// REFUSES (fail closed) rather than forgetting.

// defaultReplayEntries is the total cap. An entry lives for twice the clock
// skew (five minutes by default, so ten), and 65536 of them is about 110
// authentications per second sustained, far above what one service port sees.
const defaultReplayEntries = 1 << 16

// defaultSkew is gokrb5's, and MIT's: five minutes.
const defaultSkew = 5 * time.Minute

// perClientDivisor: one client may hold at most 1/16 of the cache, so one
// client cannot starve the others.
const perClientDivisor = 16

var (
	errReplay     = errors.New("replay detected")
	errReplayFull = errors.New("replay cache full")
)

// replayKey identifies one authenticator. Every field takes part.
type replayKey struct {
	realm, cname, sname string
	at                  time.Time // the authenticator's ctime plus its cusec
}

type replayClient struct{ realm, cname string }

type replayEntry struct {
	key     replayKey
	expires time.Time
}

type replayCache struct {
	mu        sync.Mutex
	clock     func() time.Time
	ttl       time.Duration
	max       int
	perClient int
	seen      map[replayKey]struct{}
	perCount  map[replayClient]int
	// queue holds the entries in insertion order. The expiry is the insertion
	// time plus ttl, so it is monotonic along the queue and pruning only ever
	// pops the head.
	queue []replayEntry
}

// newReplayCache returns a cache of at most max entries, each remembered for
// 2*skew: an authenticator is accepted only within skew of now, so it can be
// replayed for at most skew more after the latest moment it was accepted.
func newReplayCache(max int, skew time.Duration) *replayCache {
	if max <= 0 {
		max = defaultReplayEntries
	}
	per := max / perClientDivisor
	if per < 1 {
		per = 1
	}
	return &replayCache{
		clock:     time.Now,
		ttl:       2 * skew,
		max:       max,
		perClient: per,
		seen:      make(map[replayKey]struct{}),
		perCount:  make(map[replayClient]int),
	}
}

// admit records k, or says why it cannot: errReplay when k is already held,
// errReplayFull when the cache or the client's share is full. Check and add
// are one critical section.
func (c *replayCache) admit(k replayKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	c.prune(now)
	if _, dup := c.seen[k]; dup {
		return errReplay
	}
	cl := replayClient{k.realm, k.cname}
	if len(c.seen) >= c.max || c.perCount[cl] >= c.perClient {
		return errReplayFull
	}
	c.seen[k] = struct{}{}
	c.perCount[cl]++
	c.queue = append(c.queue, replayEntry{key: k, expires: now.Add(c.ttl)})
	return nil
}

func (c *replayCache) prune(now time.Time) {
	i := 0
	for ; i < len(c.queue) && !c.queue[i].expires.After(now); i++ {
		k := c.queue[i].key
		delete(c.seen, k)
		cl := replayClient{k.realm, k.cname}
		if c.perCount[cl]--; c.perCount[cl] <= 0 {
			delete(c.perCount, cl)
		}
	}
	if i > 0 {
		c.queue = append(c.queue[:0], c.queue[i:]...)
	}
}

func (c *replayCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
