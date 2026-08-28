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

// Package main provides helper commands to issue and assemble Merkle Tree Certificates (MTC)
// against a live Tessera POSIX MTC log, for interoperability testing with the IETF PLANTS verifier.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/transparency-dev/tessera/cmd/mtc/log"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// OID for ML-DSA-44 (2.16.840.1.101.3.4.3.17)
	oidPublicKeyMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	// OID for SHA-256 (2.16.840.1.101.3.4.2.1)
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// Draft experimental OIDs from draft-ietf-plants-merkle-tree-certs
	oidMTCProofExperiment          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}
	oidRDNATrustAnchorIDExperiment = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	oidMTCCAExperiment             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 2}
	oidAlgUnsigned                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 36}
	oidRDNAUnsigned                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 1}
)

func makeMTCName(caID string) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
		dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
				attr.AddASN1ObjectIdentifier(oidRDNATrustAnchorIDExperiment)
				attr.AddASN1(cbasn1.UTF8String, func(val *cryptobyte.Builder) {
					val.AddBytes([]byte(caID))
				})
			})
		})
	})
	return b.Bytes()
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "ca-cert":
		runCACert(os.Args[2:])
	case "policy":
		runPolicy(os.Args[2:])
	case "issue":
		runIssue(os.Args[2:])
	case "assemble":
		runAssemble(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: %s <command> [options]

Available commands:
  ca-cert    Generate an X.509 CA Certificate (ca_cert.pem) from an ML-DSA mtc.pub key
  policy     Generate a verifier policy file from an ML-DSA mirror.pub key
  issue      Generate a TBSCertificateLogEntry, submit to /add-tbs, and save response
  assemble   Assemble the X.509 MTC Certificate (cert.pem) from TBS entry and MTCProof
`, os.Args[0])
}

func runIssue(args []string) {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	logURL := fs.String("log_url", "http://localhost:6962", "Root URL of the Tessera MTC log")
	caID := fs.String("ca_id", "32473.106", "CA ID in dotted-decimal form")
	domain := fs.String("domain", "example.com", "Subject CommonName / domain")
	subscriberPub := fs.String("subscriber_pub", "", "Path to subscriber public key PEM file (required)")
	lifetime := fs.Duration("lifetime", 24*time.Hour, "Certificate validity lifetime (max 47 days)")
	outEntry := fs.String("out_entry", "entry.json", "Output path for the generated TBSCertificateLogEntry JSON")
	outResponse := fs.String("out_response", "response.json", "Output path for the AddTBSRsp JSON")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if *subscriberPub == "" {
		fmt.Fprintln(os.Stderr, "Error: --subscriber_pub flag is required")
		fs.Usage()
		os.Exit(1)
	}

	// 1. Read subscriber public key
	pubPEM, err := os.ReadFile(*subscriberPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read subscriber public key: %v\n", err)
		os.Exit(1)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		fmt.Fprintln(os.Stderr, "Failed to decode PEM block from subscriber public key")
		os.Exit(1)
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse public key: %v\n", err)
		os.Exit(1)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal SPKI: %v\n", err)
		os.Exit(1)
	}

	// 2. Issuer RDN Sequence (MTC TrustAnchorID format)
	issuerDER, err := makeMTCName(*caID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal issuer: %v\n", err)
		os.Exit(1)
	}

	// 3. Validity sequence
	type validity struct {
		NotBefore time.Time `asn1:"utc"`
		NotAfter  time.Time `asn1:"utc"`
	}
	now := time.Now().UTC().Truncate(time.Second)
	valDER, err := asn1.Marshal(validity{
		NotBefore: now,
		NotAfter:  now.Add(*lifetime),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal validity: %v\n", err)
		os.Exit(1)
	}

	// 4. Subject RDN Sequence
	subject := pkix.Name{CommonName: *domain}
	subjectDER, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal subject: %v\n", err)
		os.Exit(1)
	}

	// 5. Extract Subject Public Key Algorithm Identifier directly from SPKI DER
	spkiStr := cryptobyte.String(spkiDER)
	var spkiSeq, algDER cryptobyte.String
	if !spkiStr.ReadASN1(&spkiSeq, cbasn1.SEQUENCE) ||
		!spkiStr.Empty() ||
		!spkiSeq.ReadASN1Element(&algDER, cbasn1.SEQUENCE) {
		fmt.Fprintf(os.Stderr, "Failed to parse algorithm from SPKI\n")
		os.Exit(1)
	}

	// 6. SPKI Hash
	spkiHash := sha256.Sum256(spkiDER)

	entry := log.TBSCertificateLogEntry{
		Version:                   2,
		Issuer:                    issuerDER,
		Validity:                  valDER,
		Subject:                   subjectDER,
		SubjectPublicKeyAlgorithm: algDER,
		SubjectPublicKeyInfoHash:  spkiHash[:],
	}

	reqBody, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal TBSCertificateLogEntry: %v\n", err)
		os.Exit(1)
	}

	u, err := url.Parse(*logURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid log URL: %v\n", err)
		os.Exit(1)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/add-tbs"

	resp, err := http.Post(u.String(), "application/json", bytes.NewReader(reqBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HTTP request to /add-tbs failed: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response body: %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Server returned status %d: %s\n", resp.StatusCode, respBody)
		os.Exit(1)
	}

	var rsp log.AddTBSRsp
	if err := json.Unmarshal(respBody, &rsp); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse AddTBSRsp: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outEntry, reqBody, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", *outEntry, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outResponse, respBody, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", *outResponse, err)
		os.Exit(1)
	}

	fmt.Printf("Successfully issued certificate!\n")
	fmt.Printf("  Log Index:        %d\n", rsp.Index)
	fmt.Printf("  MTCProof Size:    %d bytes\n", len(rsp.MTCProof))
	fmt.Printf("  Saved Entry:      %s\n", *outEntry)
	fmt.Printf("  Saved Response:   %s\n", *outResponse)
}

func runAssemble(args []string) {
	fs := flag.NewFlagSet("assemble", flag.ExitOnError)
	entryPath := fs.String("entry_path", "entry.json", "Path to the TBSCertificateLogEntry JSON file")
	responsePath := fs.String("response_path", "response.json", "Path to the AddTBSRsp JSON file")
	subscriberPub := fs.String("subscriber_pub", "", "Path to subscriber public key PEM file (required)")
	_ = fs.String("ca_id", "", "Optional CA ID (included for compatibility)")
	logNumber := fs.Uint64("log_number", 1, "Log number (strictly positive)")
	outCert := fs.String("out_cert", "cert.pem", "Output path for the assembled X.509 MTC Certificate PEM")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if *subscriberPub == "" {
		fmt.Fprintln(os.Stderr, "Error: --subscriber_pub flag is required")
		fs.Usage()
		os.Exit(1)
	}

	entryBytes, err := os.ReadFile(*entryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read entry file: %v\n", err)
		os.Exit(1)
	}
	var entry log.TBSCertificateLogEntry
	if err := json.Unmarshal(entryBytes, &entry); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse entry JSON: %v\n", err)
		os.Exit(1)
	}

	rspBytes, err := os.ReadFile(*responsePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response file: %v\n", err)
		os.Exit(1)
	}
	var rsp log.AddTBSRsp
	if err := json.Unmarshal(rspBytes, &rsp); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse response JSON: %v\n", err)
		os.Exit(1)
	}

	pubPEM, err := os.ReadFile(*subscriberPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read subscriber public key: %v\n", err)
		os.Exit(1)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		fmt.Fprintln(os.Stderr, "Failed to decode PEM block from subscriber public key")
		os.Exit(1)
	}

	// Serial number calculation: (logNumber << 48) | index
	serialNum := (*logNumber << 48) | rsp.Index

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(cert *cryptobyte.Builder) {
		cert.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
			// Version v3: [0] EXPLICIT 2
			tbs.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(vers *cryptobyte.Builder) {
				vers.AddASN1Uint64(2)
			})
			tbs.AddASN1Uint64(serialNum)
			tbs.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
				alg.AddASN1ObjectIdentifier(oidMTCProofExperiment)
			})
			tbs.AddBytes(entry.Issuer)
			tbs.AddBytes(entry.Validity)
			tbs.AddBytes(entry.Subject)
			tbs.AddBytes(block.Bytes) // SPKI
		})
		cert.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
			alg.AddASN1ObjectIdentifier(oidMTCProofExperiment)
		})
		cert.AddASN1BitString(rsp.MTCProof)
	})

	certDER, err := b.Bytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to assemble X.509 certificate: %v\n", err)
		os.Exit(1)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := os.MkdirAll(filepath.Dir(*outCert), 0755); err != nil && filepath.Dir(*outCert) != "." {
		fmt.Fprintf(os.Stderr, "Failed to create directory for certificate: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outCert, certPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", *outCert, err)
		os.Exit(1)
	}

	fmt.Printf("Successfully assembled X.509 MTC Certificate!\n")
	fmt.Printf("  Serial Number:    %d\n", serialNum)
	fmt.Printf("  Sig Algorithm:    %s\n", oidMTCProofExperiment.String())
	fmt.Printf("  Output PEM:       %s\n", *outCert)
}

func runCACert(args []string) {
	fs := flag.NewFlagSet("ca-cert", flag.ExitOnError)
	caID := fs.String("ca_id", "32473.106", "CA ID in dotted-decimal form")
	caPub := fs.String("ca_pub", "", "Path to the note-formatted mtc.pub public key file (required)")
	outCert := fs.String("out_cert", "ca_cert.pem", "Output path for the generated CA certificate PEM")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if *caPub == "" {
		fmt.Fprintln(os.Stderr, "Error: --ca_pub flag is required")
		fs.Usage()
		os.Exit(1)
	}

	pubBytes, err := os.ReadFile(*caPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read CA public key %s: %v\n", *caPub, err)
		os.Exit(1)
	}

	// mtc.pub format: <name>+<keyhash>+<base64_mldsa_pubkey>
	pubStr := strings.TrimSpace(string(pubBytes))
	parts := strings.SplitN(pubStr, "+", 3)
	if len(parts) < 3 {
		fmt.Fprintf(os.Stderr, "Invalid note public key format in %s\n", *caPub)
		os.Exit(1)
	}
	rawDecoded, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode base64 public key: %v\n", err)
		os.Exit(1)
	}
	// The first byte in cosignature v1 vkey format is the algorithm ID (0x06 for ML-DSA-44).
	// Strip it to get the raw 1312-byte ML-DSA-44 public key.
	rawPubKey := rawDecoded
	if len(rawDecoded) == 1313 {
		rawPubKey = rawDecoded[1:]
	}

	// Build SubjectPublicKeyInfo for ML-DSA-44
	type spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	spkiObj := spki{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyMLDSA44},
		PublicKey: asn1.BitString{Bytes: rawPubKey, BitLength: len(rawPubKey) * 8},
	}
	spkiDER, err := asn1.Marshal(spkiObj)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal SPKI: %v\n", err)
		os.Exit(1)
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(cert *cryptobyte.Builder) {
		cert.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
			// Version v3: [0] EXPLICIT 2
			tbs.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(vers *cryptobyte.Builder) {
				vers.AddASN1Uint64(2)
			})
			tbs.AddASN1Uint64(1) // Serial Number = 1
			// Unsigned sig alg: SEQUENCE { OID(1.3.6.1.5.5.7.6.36) }
			tbs.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
				alg.AddASN1ObjectIdentifier(oidAlgUnsigned)
			})
			// Issuer placeholder: SEQUENCE { SET { SEQUENCE { OID(1.3.6.1.5.5.7.25.1), UTF8String("") } } }
			tbs.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
				dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
					rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
						attr.AddASN1ObjectIdentifier(oidRDNAUnsigned)
						attr.AddASN1(cbasn1.UTF8String, func(val *cryptobyte.Builder) {})
					})
				})
			})
			// Validity
			now := time.Now().UTC().Add(-24 * time.Hour)
			tbs.AddASN1(cbasn1.SEQUENCE, func(val *cryptobyte.Builder) {
				val.AddASN1UTCTime(now)
				val.AddASN1UTCTime(now.Add(10 * 365 * 24 * time.Hour))
			})
			// Subject: SEQUENCE { SET { SEQUENCE { OID(1.3.6.1.4.1.44363.47.1), UTF8String(caID) } } }
			tbs.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
				dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
					rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
						attr.AddASN1ObjectIdentifier(oidRDNATrustAnchorIDExperiment)
						attr.AddASN1(cbasn1.UTF8String, func(val *cryptobyte.Builder) {
							val.AddBytes([]byte(*caID))
						})
					})
				})
			})
			// SPKI
			tbs.AddBytes(spkiDER)
			// Extensions: [3] EXPLICIT Extensions
			tbs.AddASN1(cbasn1.Tag(3).Constructed().ContextSpecific(), func(exts *cryptobyte.Builder) {
				exts.AddASN1(cbasn1.SEQUENCE, func(extList *cryptobyte.Builder) {
					extList.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
						ext.AddASN1ObjectIdentifier(oidMTCCAExperiment)
						ext.AddASN1Boolean(true) // Critical: true
						ext.AddASN1(cbasn1.OCTET_STRING, func(extVal *cryptobyte.Builder) {
							extVal.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
								seq.AddASN1(cbasn1.SEQUENCE, func(lh *cryptobyte.Builder) {
									lh.AddASN1ObjectIdentifier(oidSHA256)
								})
								seq.AddASN1(cbasn1.SEQUENCE, func(sa *cryptobyte.Builder) {
									sa.AddASN1ObjectIdentifier(oidPublicKeyMLDSA44)
								})
								seq.AddASN1Uint64(0)
								seq.AddASN1Uint64(math.MaxUint64)
							})
						})
					})
				})
			})
		})
		cert.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
			alg.AddASN1ObjectIdentifier(oidAlgUnsigned)
		})
		cert.AddASN1BitString(nil)
	})

	certDER, err := b.Bytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal CA certificate DER: %v\n", err)
		os.Exit(1)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := os.MkdirAll(filepath.Dir(*outCert), 0755); err != nil && filepath.Dir(*outCert) != "." {
		fmt.Fprintf(os.Stderr, "Failed to create directory for CA certificate: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outCert, certPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", *outCert, err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated CA Certificate!\n")
	fmt.Printf("  CA ID:            %s\n", *caID)
	fmt.Printf("  Key Algorithm:    ML-DSA-44\n")
	fmt.Printf("  Output PEM:       %s\n", *outCert)
}

func runPolicy(args []string) {
	fs := flag.NewFlagSet("policy", flag.ExitOnError)
	cosignerID := fs.String("cosigner_id", "32473.312202", "Cosigner ID in dotted-decimal form")
	mirrorPub := fs.String("mirror_pub", "", "Path to the note-formatted mirror.pub public key file (required)")
	outPolicy := fs.String("out_policy", "policy", "Output path for the generated verifier policy file")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if *mirrorPub == "" {
		fmt.Fprintln(os.Stderr, "Error: --mirror_pub flag is required")
		fs.Usage()
		os.Exit(1)
	}

	pubBytes, err := os.ReadFile(*mirrorPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read mirror public key %s: %v\n", *mirrorPub, err)
		os.Exit(1)
	}

	pubStr := strings.TrimSpace(string(pubBytes))
	parts := strings.SplitN(pubStr, "+", 3)
	if len(parts) < 3 {
		fmt.Fprintf(os.Stderr, "Invalid note public key format in %s\n", *mirrorPub)
		os.Exit(1)
	}
	rawDecoded, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode base64 public key: %v\n", err)
		os.Exit(1)
	}
	rawPubKey := rawDecoded
	if len(rawDecoded) == 1313 {
		rawPubKey = rawDecoded[1:]
	}

	// Build SubjectPublicKeyInfo for ML-DSA-44
	type spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	spkiObj := spki{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyMLDSA44},
		PublicKey: asn1.BitString{Bytes: rawPubKey, BitLength: len(rawPubKey) * 8},
	}
	spkiDER, err := asn1.Marshal(spkiObj)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal SPKI: %v\n", err)
		os.Exit(1)
	}
	spkiB64 := base64.StdEncoding.EncodeToString(spkiDER)

	policyText := fmt.Sprintf(`# MTC Verifier Trust Policy
cosigner %s mldsa44 %s
group g1 all %s
require-cosigners all g1
`, *cosignerID, spkiB64, *cosignerID)

	if err := os.MkdirAll(filepath.Dir(*outPolicy), 0755); err != nil && filepath.Dir(*outPolicy) != "." {
		fmt.Fprintf(os.Stderr, "Failed to create directory for policy file: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPolicy, []byte(policyText), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", *outPolicy, err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated Policy file!\n")
	fmt.Printf("  Cosigner ID:      %s\n", *cosignerID)
	fmt.Printf("  Output Policy:    %s\n", *outPolicy)
}
