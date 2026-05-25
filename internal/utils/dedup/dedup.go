package dedup

import "sync"

type Set struct {
	mu    sync.Mutex
	items map[string]struct{}
}

func New() *Set { return &Set{items: make(map[string]struct{})} }

// Add returns true if the item is new (not a duplicate).
func (s *Set) Add(v string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[v]; ok {
		return false
	}
	s.items[v] = struct{}{}
	return true
}

func (s *Set) Slice() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.items))
	for k := range s.items {
		out = append(out, k)
	}
	return out
}
