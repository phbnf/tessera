// Copyright 2026 The Tessera authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checkpoint

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/transparency-dev/tessera/internal/parse"
)

// Reader wraps a ReadCheckpoint function to cache the latest checkpoint size with a TTL.
type Reader struct {
	readCheckpoint func(context.Context) ([]byte, error)
	ttl            time.Duration

	mu          sync.RWMutex
	latest      uint64
	lastFetched time.Time
}

// NewReader creates a new Reader instance wrapping readCheckpoint with the given TTL.
func NewReader(readCheckpoint func(context.Context) ([]byte, error), ttl time.Duration) *Reader {
	return &Reader{
		readCheckpoint: readCheckpoint,
		ttl:            ttl,
	}
}

// ReadCheckpoint reads the latest checkpoint from underlying storage and updates the in-memory cache.
func (r *Reader) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	rawCp, err := r.readCheckpoint(ctx)
	if err != nil {
		return nil, err
	}

	_, size, _, err := parse.CheckpointUnsafe(rawCp)
	if err != nil {
		return nil, fmt.Errorf("parse checkpoint: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.latest = size
	r.lastFetched = time.Now()

	return rawCp, nil
}

// ReadCheckpointSizeCached returns the most recently observed checkpoint size.
// If the cached value is stale (older than TTL) or unset, it refreshes from storage.
func (r *Reader) ReadCheckpointSizeCached(ctx context.Context) (uint64, error) {
	r.mu.RLock()
	if !r.lastFetched.IsZero() && time.Since(r.lastFetched) < r.ttl && r.latest > 0 {
		size := r.latest
		r.mu.RUnlock()
		return size, nil
	}
	r.mu.RUnlock()

	if _, err := r.ReadCheckpoint(ctx); err != nil {
		return 0, err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.latest, nil
}
