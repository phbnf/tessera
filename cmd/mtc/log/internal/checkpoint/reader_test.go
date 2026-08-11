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
	"testing"
	"time"
)

func mockCheckpoint(origin string, size uint64) []byte {
	return []byte(fmt.Sprintf("%s\n%d\nAAAA\n", origin, size))
}

func TestReader_ReadCheckpointSizeCached(t *testing.T) {
	ctx := context.Background()
	currentSize := uint64(10)
	readCalls := 0

	readCP := func(_ context.Context) ([]byte, error) {
		readCalls++
		return mockCheckpoint("test.log", currentSize), nil
	}

	ttl := 50 * time.Millisecond
	r := NewReader(readCP, ttl)

	// First call triggers fetch
	size, err := r.ReadCheckpointSizeCached(ctx)
	if err != nil {
		t.Fatalf("ReadCheckpointSizeCached() error: %v", err)
	}
	if size != 10 {
		t.Errorf("ReadCheckpointSizeCached() = %d, want 10", size)
	}
	if readCalls != 1 {
		t.Errorf("readCalls = %d, want 1", readCalls)
	}

	// Second call within TTL returns cached value
	currentSize = 20
	size, err = r.ReadCheckpointSizeCached(ctx)
	if err != nil {
		t.Fatalf("ReadCheckpointSizeCached() error: %v", err)
	}
	if size != 10 {
		t.Errorf("ReadCheckpointSizeCached() cached = %d, want 10", size)
	}
	if readCalls != 1 {
		t.Errorf("readCalls within TTL = %d, want 1", readCalls)
	}

	// Wait for TTL to expire, call again
	time.Sleep(ttl + 10*time.Millisecond)
	size, err = r.ReadCheckpointSizeCached(ctx)
	if err != nil {
		t.Fatalf("ReadCheckpointSizeCached() after TTL error: %v", err)
	}
	if size != 20 {
		t.Errorf("ReadCheckpointSizeCached() refreshed = %d, want 20", size)
	}
	if readCalls != 2 {
		t.Errorf("readCalls after TTL = %d, want 2", readCalls)
	}
}

func TestReader_ReadCheckpoint(t *testing.T) {
	ctx := context.Background()
	currentSize := uint64(100)

	readCP := func(_ context.Context) ([]byte, error) {
		return mockCheckpoint("test.log", currentSize), nil
	}

	r := NewReader(readCP, 1*time.Minute)

	cp, err := r.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("ReadCheckpoint() error: %v", err)
	}
	if len(cp) == 0 {
		t.Fatal("ReadCheckpoint() returned empty slice")
	}

	size, err := r.ReadCheckpointSizeCached(ctx)
	if err != nil {
		t.Fatalf("ReadCheckpointSizeCached() error: %v", err)
	}
	if size != 100 {
		t.Errorf("ReadCheckpointSizeCached() = %d, want 100", size)
	}
}
