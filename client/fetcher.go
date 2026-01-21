// Copyright 2024 The Tessera authors. All Rights Reserved.
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

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/internal/fetcher"
	"k8s.io/klog/v2"
)

var (
	errMalformedNote      = errors.New("malformed note")
	errInvalidSigner      = errors.New("invalid signer")
	errMismatchedVerifier = errors.New("verifier name or hash doesn't match signature")

	sigSplit  = []byte("\n\n")
	sigPrefix = []byte("— ")
)

// NewHTTPFetcher creates a new HTTPFetcher for the log rooted at the given URL, using
// the provided HTTP client.
//
// rootURL should end in a trailing slash.
// c may be nil, in which case http.DefaultClient will be used.
func NewHTTPFetcher(rootURL *url.URL, c *http.Client) (*HTTPFetcher, error) {
	if !strings.HasSuffix(rootURL.String(), "/") {
		rootURL.Path += "/"
	}
	if c == nil {
		c = http.DefaultClient
	}
	return &HTTPFetcher{
		c:       c,
		rootURL: rootURL,
	}, nil
}

// HTTPFetcher knows how to fetch log artifacts from a log being served via HTTP.
type HTTPFetcher struct {
	c          *http.Client
	rootURL    *url.URL
	authHeader string
}

// SetAuthorizationHeader sets the value to be used with an Authorization: header
// for every request made by this fetcher.
func (h *HTTPFetcher) SetAuthorizationHeader(v string) {
	h.authHeader = v
}

func (h HTTPFetcher) fetch(ctx context.Context, p string) ([]byte, error) {
	u, err := h.rootURL.Parse(p)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("NewRequestWithContext(%q): %v", u.String(), err)
	}
	if h.authHeader != "" {
		req.Header.Add("Authorization", h.authHeader)
	}
	r, err := h.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get(%q): %v", u.String(), err)
	}
	switch r.StatusCode {
	case http.StatusOK:
		// All good, continue below
	case http.StatusNotFound:
		// Need to return ErrNotExist here, by contract.
		return nil, fmt.Errorf("get(%q): %w", u.String(), os.ErrNotExist)
	default:
		return nil, fmt.Errorf("get(%q): %v", u.String(), r.StatusCode)
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			klog.Errorf("resp.Body.Close(): %v", err)
		}
	}()
	return io.ReadAll(r.Body)
}

func (h HTTPFetcher) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	cpkt, err := h.fetch(ctx, layout.CheckpointPath)
	if err != nil {
		return nil, err
	}

	fmt.Println("Old CKPT")
	fmt.Println(string(cpkt))
	fmt.Println("Old CKPT")
	ncpkt, err := crosModify(cpkt)
	if err != nil {
		return nil, fmt.Errorf("crosModify: %v", err)
	}
	fmt.Println("New CKPT")
	fmt.Println(string(ncpkt))
	fmt.Println("New CKPT")
	return ncpkt, nil
}

func crosModify(msg []byte) ([]byte, error) {
	// Must have valid UTF-8 with no non-newline ASCII control characters.
	for i := 0; i < len(msg); {
		r, size := utf8.DecodeRune(msg[i:])
		if r < 0x20 && r != '\n' || r == utf8.RuneError && size == 1 {
			return nil, errMalformedNote
		}
		i += size
	}

	// Must end with signature block preceded by blank line.
	sigSplit := []byte("\n\n")
	sigPrefix := []byte("— ")
	split := bytes.LastIndex(msg, sigSplit)
	if split < 0 {
		return nil, errMalformedNote
	}
	text, sigs := msg[:split+1], msg[split+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, errMalformedNote
	}

	newSigs := []byte{}
	count := 0
	for len(sigs) > 0 {
		// Pull out next signature line.
		// We know sigs[len(sigs)-1] == '\n', so IndexByte always finds one.
		i := bytes.IndexByte(sigs, '\n')
		line := sigs[:i]
		sigs = sigs[i+1:]

		if !bytes.HasPrefix(line, sigPrefix) {
			return nil, errMalformedNote
		}
		line = line[len(sigPrefix):]
		name, b64, _ := strings.Cut(string(line), " ")
		sig, err := base64.StdEncoding.DecodeString(b64)
		if err != nil { //|| !isValidName(name) || b64 == "" || len(sig) < 5 {
			return nil, errMalformedNote
		}
		//hash :=
		keyID := sig[0:4]
		tinkKeyID := binary.BigEndian.Uint32(sig[0:4])
		fmt.Printf("Old keyID: %d\n", tinkKeyID)
		fmt.Printf("Old keyID: %08x\n", keyID)
		if name == "recoverylog.chromebook.com" {
			if count == 0 {
				count += 1
				//	continue
			}
			input := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW_0IGDyIKy_lA10CIjNV4dy3G1jVLIhabzRLJJDSD9nesZLv6Pqe0MVRGjncQkCjh4lOwOsOwMbdRaux8R912w=="
			rawBytes, err := base64.URLEncoding.DecodeString(input)
			if err != nil {
				log.Fatalf("Failed to decode: %v", err)
			}
			fullKeyID := sha256.Sum256(rawBytes)
			keyID = fullKeyID[0:4]
			fmt.Printf("New keyID: %08x\n", keyID)
		}
		newSig := []byte{}
		newSig = append(newSig, keyID...)
		newSig = append(newSig, sig[4:]...)
		newSigStr := base64.StdEncoding.EncodeToString(newSig)
		newSigs = append(newSigs, []byte(fmt.Sprintf("%s%s %s\n", sigPrefix, name, newSigStr))...)
		if name == "recoverylog.chromebook.com" {
			break
		}
	}
	note := []byte{}
	note = append(note, text...)
	note = append(note, []byte("\n")...)
	note = append(note, newSigs...)
	return note, nil
}

func (h HTTPFetcher) ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error) {
	return fetcher.PartialOrFullResource(ctx, p, func(ctx context.Context, p uint8) ([]byte, error) {
		return h.fetch(ctx, layout.TilePath(l, i, p))
	})
}

func (h HTTPFetcher) ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error) {
	return fetcher.PartialOrFullResource(ctx, p, func(ctx context.Context, p uint8) ([]byte, error) {
		return h.fetch(ctx, layout.EntriesPath(i, p))
	})
}

// FileFetcher knows how to fetch log artifacts from a filesystem rooted at Root.
type FileFetcher struct {
	Root string
}

func (f FileFetcher) ReadCheckpoint(_ context.Context) ([]byte, error) {
	return os.ReadFile(path.Join(f.Root, layout.CheckpointPath))
}

func (f FileFetcher) ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error) {
	return fetcher.PartialOrFullResource(ctx, p, func(ctx context.Context, p uint8) ([]byte, error) {
		return os.ReadFile(path.Join(f.Root, layout.TilePath(l, i, p)))
	})
}

func (f FileFetcher) ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error) {
	return fetcher.PartialOrFullResource(ctx, p, func(ctx context.Context, p uint8) ([]byte, error) {
		return os.ReadFile(path.Join(f.Root, layout.EntriesPath(i, p)))
	})
}
