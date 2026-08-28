# MTC Log & Mirror Interoperability Integration Tests

This directory contains helper tools and full step-by-step instructions to:
1. Bring up a **Tessera POSIX MTC Log** and matching **POSIX Mirror / Witness**.
2. Generate a valid **`TBSCertificate`** (with valid duration $\le 47$ days) and submit it to `POST /add-tbs`.
3. Assemble the resulting **`TBSCertificate`** + **`MTCProof`** into a standard **X.509 MTC Certificate (`cert.pem`)**.
4. Verify the issued certificate using the official [IETF PLANTS MTC Demo Verifier](https://github.com/ietf-plants-wg/merkle-tree-certs/tree/main/demo) (`./demo verify`).

---

## 1. Prerequisites

### Build the IETF PLANTS MTC Demo Verifier
Clone and build the verifier from the IETF repository:
```bash
git clone https://github.com/ietf-plants-wg/merkle-tree-certs.git /tmp/ietf-mtc
cd /tmp/ietf-mtc/demo
go build -o /tmp/demo .
```

### Prepare a Scratch Directory
```bash
mkdir -p /tmp/mtc_test/keys /tmp/mtc_test/log /tmp/mtc_test/mirror
```

---

## 2. Generate Cryptographic Keys

### 2.1 CA and Mirror ML-DSA Keys
Generate the ML-DSA key pairs in `vkey` format:

```bash
# CA Key Pair (CA ID: 32473.106)
go run github.com/transparency-dev/witness/cmd/generate_keys@main \
  --mldsa \
  --origin "oid/1.3.6.1.4.1.32473.106" \
  --out_priv /tmp/mtc_test/keys/mtc.sec \
  --out_pub /tmp/mtc_test/keys/mtc.pub

# Mirror / Witness Key Pair (Cosigner ID: 32473.312202)
go run github.com/transparency-dev/witness/cmd/generate_keys@main \
  --mldsa \
  --origin "oid/1.3.6.1.4.1.32473.312202" \
  --out_priv /tmp/mtc_test/keys/mirror.sec \
  --out_pub /tmp/mtc_test/keys/mirror.pub
```

### 2.2 Subscriber (End-Entity) Key Pair
Generate an ECDSA P-256 key pair for the certificate to be issued:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/mtc_test/keys/subscriber.key
openssl ec -in /tmp/mtc_test/keys/subscriber.key -pubout -out /tmp/mtc_test/keys/subscriber.pub
```

### 2.3 CA Certificate (for the Verifier)
Generate the CA certificate (`ca_cert.pem`) from the ML-DSA CA public key:

```bash
go run ./cmd/mtc/integration_tests ca-cert \
  --ca_id="32473.106" \
  --ca_pub="/tmp/mtc_test/keys/mtc.pub" \
  --out_cert="/tmp/mtc_test/keys/ca_cert.pem"
```

---

## 3. Configure and Start Services

### 3.1 Start the POSIX Mirror Server
Create the mirror target configuration:
```bash
cat <<EOF > /tmp/mtc_test/mirror_config
logs/v0

vkey $(cat /tmp/mtc_test/keys/mtc.pub)
origin oid/1.3.6.1.4.1.32473.106.0.1
EOF
```

In **Terminal 1**, start the mirror:
```bash
go run ./cmd/mtc/mirror/posix \
  --listen_addr="localhost:6963" \
  --storage_dir="/tmp/mtc_test/mirror" \
  --config_path="/tmp/mtc_test/mirror_config" \
  --mirror_cosigner_path="/tmp/mtc_test/keys/mirror.sec" \
  --slog_level=-4
```

### 3.2 Start the POSIX MTC Log Server
Create the mirror policy configuration:
```bash
cat <<EOF > /tmp/mtc_test/mirror_policy
witness w1 $(cat /tmp/mtc_test/keys/mirror.pub) http://localhost:6963/
group g1 all w1
quorum g1
EOF
```

In **Terminal 2**, start the log server:
```bash
go run ./cmd/mtc/log/posix \
  --listen_addr="localhost:6962" \
  --storage_dir="/tmp/mtc_test/log" \
  --ca_id="32473.106" \
  --log_number=1 \
  --private_key="/tmp/mtc_test/keys/mtc.sec" \
  --mirror_policy="/tmp/mtc_test/mirror_policy" \
  --slog_level=-4
```

---

## 4. Issue and Assemble the Certificate

### 4.1 Generate TBS and Request Proof (`issue`)
In **Terminal 3**, run the `issue` command. This automatically creates a DER-encoded `TBSCertificateLogEntry` with valid issuer, subject, validity ($\le 47$ days), and SPKI hash, and submits it to `POST http://localhost:6962/add-tbs`:

```bash
go run ./cmd/mtc/integration_tests issue \
  --log_url="http://localhost:6962" \
  --ca_id="32473.106" \
  --domain="example.com" \
  --subscriber_pub="/tmp/mtc_test/keys/subscriber.pub" \
  --lifetime=24h \
  --out_entry="/tmp/mtc_test/entry.json" \
  --out_response="/tmp/mtc_test/response.json"
```

### 4.2 Assemble the X.509 MTC Certificate (`assemble`)
Run the `assemble` command to wrap the `TBSCertificate` and `MTCProof` into standard X.509 PEM format:

```bash
go run ./cmd/mtc/integration_tests assemble \
  --entry_path="/tmp/mtc_test/entry.json" \
  --response_path="/tmp/mtc_test/response.json" \
  --subscriber_pub="/tmp/mtc_test/keys/subscriber.pub" \
  --ca_id="32473.106" \
  --log_number=1 \
  --out_cert="/tmp/mtc_test/cert.pem"
```

---

## 5. Verify with the IETF Demo Verifier

### 5.1 Create the Verifier Policy File
Generate the verifier policy file from the ML-DSA mirror public key:

```bash
go run ./cmd/mtc/integration_tests policy \
  --cosigner_id="32473.312202" \
  --mirror_pub="/tmp/mtc_test/keys/mirror.pub" \
  --out_policy="/tmp/mtc_test/policy"
```

### 5.2 Run `./demo verify`
Verify the assembled certificate:

```bash
/tmp/demo verify \
  --ca-cert /tmp/mtc_test/keys/ca_cert.pem \
  --policy /tmp/mtc_test/policy \
  /tmp/mtc_test/cert.pem
```

---

## 6. Helper CLI Reference

```text
Usage: go run ./cmd/mtc/integration_tests <command> [options]

Available commands:
  ca-cert    Generate an X.509 CA Certificate (ca_cert.pem) from an ML-DSA mtc.pub key
  policy     Generate a verifier policy file from an ML-DSA mirror.pub key
  issue      Generate a TBSCertificateLogEntry, submit to /add-tbs, and save response
  assemble   Assemble the X.509 MTC Certificate (cert.pem) from TBS entry and MTCProof
```

### `ca-cert` Flags
- `--ca_id`: CA ID in dotted-decimal form (default `32473.106`).
- `--ca_pub`: Path to the note-formatted `mtc.pub` public key file (**required**).
- `--out_cert`: Output path for the generated CA certificate PEM (default `ca_cert.pem`).

### `policy` Flags
- `--cosigner_id`: Cosigner ID in dotted-decimal form (default `32473.312202`).
- `--mirror_pub`: Path to the note-formatted `mirror.pub` public key file (**required**).
- `--out_policy`: Output path for the generated policy file (default `policy`).

### `issue` Flags
- `--log_url`: Root URL of the Tessera MTC log (default `http://localhost:6962`).
- `--ca_id`: CA ID in dotted-decimal form (default `32473.106`).
- `--domain`: Subject domain/CommonName (default `example.com`).
- `--subscriber_pub`: Path to subscriber public key PEM file (**required**).
- `--lifetime`: Certificate validity lifetime (default `24h`, max `47d`).
- `--out_entry`: Output path for `TBSCertificateLogEntry` JSON (default `entry.json`).
- `--out_response`: Output path for `AddTBSRsp` JSON (default `response.json`).

### `assemble` Flags
- `--entry_path`: Path to `TBSCertificateLogEntry` JSON file (default `entry.json`).
- `--response_path`: Path to `AddTBSRsp` JSON file (default `response.json`).
- `--subscriber_pub`: Path to subscriber public key PEM file (**required**).
- `--ca_id`: CA ID in dotted-decimal form (default `32473.106`).
- `--log_number`: Log number (default `1`).
- `--out_cert`: Output path for assembled `cert.pem` (default `cert.pem`).
