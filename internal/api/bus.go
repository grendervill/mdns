package api

import "sync"

// Event is one live update published to /events subscribers.
type Event struct {
	Type string // requests | upstreams | filter
	Data any
}

// subscriberBuffer is how many events a slow subscriber may lag by
// before events are dropped for it.
const subscriberBuffer = 64

// Bus fans events out to subscribers without blocking publishers. It
// is safe for concurrent use.
type Bus struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

// NewBus builds an empty bus.
func NewBus() *Bus {
	return &Bus{subs: make(map[chan Event]struct{})}
}

// Publish delivers e to every subscriber; a subscriber whose buffer is
// full loses the event rather than stalling the publisher.
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default: // drop for a slow subscriber
		}
	}
}

// Subscribe returns a channel of events and a cancel function; calling
// cancel removes the subscription and closes the channel.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, subscriberBuffer)

	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, ch)
			b.mu.Unlock()
			close(ch)
		})
	}
	return ch, cancel
}

// Subscribers reports the live subscription count (for tests and
// diagnostics).
func (b *Bus) Subscribers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}
