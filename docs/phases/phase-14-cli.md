# Phase 14 — CLI Tool `cmd/dstu`

## Goal
Implement a command-line interface tool (`dstu`) that exposes the full `ua` package API as a standalone binary, similar in spirit to `dstucrypt/agent`. The tool covers sign, verify/unwrap, encrypt, decrypt, cert-info, and key-unprotect operations with all the options used in real Ukrainian tax office workflows.

## Prerequisites
- **Phase 12** (`ua`) — all high-level operations
- **Phase 7** (`keystore`) — key loading
- **Phase 8** (`cert`) — certificate parsing
- **Phase 11** (`tsp`) — timestamp support

## Package
`github.com/amaneshi/crypto-dstu/cmd/dstu`

## Reference
- `dstucrypt/agent` README — CLI flags and workflow descriptions
- `ua/box.go` — `Box` context, `SignDocument`, `UnsignDocument`, `EncryptDocument`, `DecryptDocument`

---

## Files to Create

| File | Purpose |
|------|---------|
| `cmd/dstu/main.go` | Entry point, flag parsing, dispatch to subcommands |
| `cmd/dstu/cmd_sign.go` | `sign` subcommand |
| `cmd/dstu/cmd_decrypt.go` | `decrypt` / unwrap subcommand |
| `cmd/dstu/cmd_encrypt.go` | `encrypt` subcommand |
| `cmd/dstu/cmd_certinfo.go` | `certinfo` subcommand |
| `cmd/dstu/cmd_unprotect.go` | `unprotect` subcommand (strip key password) |
| `cmd/dstu/flags.go` | Shared flag definitions and helpers |

---

## Step-by-Step Instructions

### 1. Entry point and flag parsing (`main.go`)

Use Go's `flag` standard library. Dispatch based on the first subcommand argument (`sign`, `decrypt`, `encrypt`, `certinfo`, `unprotect`). Print usage to stderr and exit 1 on error.

```go
package main

import (
    "flag"
    "fmt"
    "os"
)

func main() {
    if len(os.Args) < 2 {
        usage()
        os.Exit(1)
    }
    switch os.Args[1] {
    case "sign":
        runSign(os.Args[2:])
    case "decrypt", "unwrap":
        runDecrypt(os.Args[2:])
    case "encrypt":
        runEncrypt(os.Args[2:])
    case "certinfo":
        runCertInfo(os.Args[2:])
    case "unprotect":
        runUnprotect(os.Args[2:])
    default:
        fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
        usage()
        os.Exit(1)
    }
}

func usage() {
    fmt.Fprintln(os.Stderr, `usage: dstu <command> [options]

commands:
  sign        Sign a document
  decrypt     Decrypt and/or verify an incoming document
  encrypt     Encrypt a document for a recipient
  certinfo    Print certificate information
  unprotect   Remove password protection from a key container
`)
}
```

### 2. Shared flags helper (`flags.go`)

Define a `commonFlags` struct and a `buildBox` helper that wires flags into a `ua.Box`.

```go
package main

import (
    "flag"
    "os"
    "strings"

    "github.com/amaneshi/crypto-dstu/ua"
)

type commonFlags struct {
    keyFlag     string   // "path:password" or "path"
    certFlags   []string // may be repeated
    caPath      string
    tspURL      string
    role        string
}

// multiFlag implements flag.Value for repeated --cert / --tsp-url flags.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
    *m = append(*m, v)
    return nil
}

func buildBox(cf commonFlags) (*ua.Box, error) {
    box := ua.NewBox()

    // Load key
    if cf.keyFlag != "" {
        parts := strings.SplitN(cf.keyFlag, ":", 2)
        path := parts[0]
        password := ""
        if len(parts) == 2 {
            password = parts[1]
        }
        if err := box.LoadKeyFile(path, password); err != nil {
            return nil, err
        }
    }

    // Load additional certs
    for _, p := range cf.certFlags {
        if err := box.AddCertFile(p); err != nil {
            return nil, err
        }
    }

    // Load CA bundle
    if cf.caPath != "" {
        if err := box.LoadCABundleFile(cf.caPath); err != nil {
            return nil, err
        }
    }

    // Configure TSP
    if cf.tspURL != "" {
        box.AddTSP(cf.tspURL)
    }

    return box, nil
}

func mustRead(path string) []byte {
    if path == "-" || path == "" {
        var buf []byte
        tmp := make([]byte, 4096)
        for {
            n, err := os.Stdin.Read(tmp)
            buf = append(buf, tmp[:n]...)
            if err != nil {
                break
            }
        }
        return buf
    }
    data, err := os.ReadFile(path)
    if err != nil {
        fatalf("read %s: %v", path, err)
    }
    return data
}

func mustWrite(path string, data []byte) {
    if path == "-" || path == "" {
        os.Stdout.Write(data)
        return
    }
    if err := os.WriteFile(path, data, 0644); err != nil {
        fatalf("write %s: %v", path, err)
    }
}

func fatalf(format string, args ...interface{}) {
    fmt.Fprintf(os.Stderr, "dstu: "+format+"\n", args...)
    os.Exit(1)
}
```

### 3. Sign command (`cmd_sign.go`)

Flags mirror `dstucrypt/agent --sign`:

```
dstu sign [flags]
  -key path[:password]    Key container (Key-6.dat, .jks, .p12, .der, .pem)
  -cert path              Signing certificate (repeatable)
  -ca path                CA bundle (.p7b or dir)
  -input path             Input file (default: stdin)
  -output path            Output file (default: stdout)
  -no-tax                 Raw CMS output; omit transport header and UA_SIGN1
  -detached               Produce detached signature
  -tsp url                TSP server URL (repeatable); adds timestamp
  -tsp-level value        Signature timestamp level: none|signature|content|all (default: none)
  -role value             Key role to use: personal|fop|director|stamp|other
  -email addr             Sender email for transport header
  -filename name          Attachment filename for transport header
  -crypt path             Recipient cert: sign-then-encrypt (optional)
  -include-chain value    Add cert chain refs: none|ref|full
```

```go
func runSign(args []string) {
    fs := flag.NewFlagSet("sign", flag.ExitOnError)
    key := fs.String("key", "", "key container path[:password]")
    var certs multiFlag
    fs.Var(&certs, "cert", "certificate file (repeatable)")
    ca := fs.String("ca", "", "CA bundle path")
    input := fs.String("input", "-", "input file")
    output := fs.String("output", "-", "output file")
    noTax := fs.Bool("no-tax", false, "raw CMS output (no transport header)")
    detached := fs.Bool("detached", false, "detached signature")
    tspLevel := fs.String("tsp-level", "none", "TSP level: none|signature|content|all")
    var tspURLs multiFlag
    fs.Var(&tspURLs, "tsp", "TSP server URL (repeatable)")
    role := fs.String("role", "", "key role")
    email := fs.String("email", "", "sender email")
    filename := fs.String("filename", "", "attachment filename")
    cryptCert := fs.String("crypt", "", "recipient cert for sign+encrypt")
    includeChain := fs.String("include-chain", "none", "cert chain: none|ref|full")
    fs.Parse(args)

    cf := commonFlags{keyFlag: *key, certFlags: certs, caPath: *ca, role: *role}
    box, err := buildBox(cf)
    if err != nil {
        fatalf("setup: %v", err)
    }
    for _, u := range tspURLs {
        box.AddTSP(u)
    }

    content := mustRead(*input)

    opts := ua.SignOptions{
        NoTax:        *noTax,
        Detached:     *detached,
        TSPLevel:     *tspLevel,
        IncludeChain: *includeChain,
        Email:        *email,
        Filename:     *filename,
    }

    var result []byte
    if *cryptCert != "" {
        recipientDER := mustRead(*cryptCert)
        result, err = box.SignAndEncryptFile(content, recipientDER, opts)
    } else {
        result, err = box.SignDocument(content, opts)
    }
    if err != nil {
        fatalf("sign: %v", err)
    }

    mustWrite(*output, result)
}
```

### 4. Decrypt/unwrap command (`cmd_decrypt.go`)

```
dstu decrypt [flags]
  -key path[:password]    Key container
  -ca path                CA bundle
  -input path             Input file
  -output path            Output file
  -tsp                    Verify timestamps
  -ocsp value             OCSP mode: strict|lax
  -role value             Key role
```

```go
func runDecrypt(args []string) {
    fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
    key := fs.String("key", "", "key container path[:password]")
    ca := fs.String("ca", "", "CA bundle path")
    input := fs.String("input", "-", "input file")
    output := fs.String("output", "-", "output file")
    role := fs.String("role", "", "key role")
    verbose := fs.Bool("v", false, "print signer info to stderr")
    fs.Parse(args)

    cf := commonFlags{keyFlag: *key, caPath: *ca, role: *role}
    box, err := buildBox(cf)
    if err != nil {
        fatalf("setup: %v", err)
    }

    data := mustRead(*input)

    // Try decrypt first, then unsign
    var content []byte
    result, err := box.UnsignDocument(data)
    if err != nil {
        // Try decrypt-then-unsign
        plain, err2 := box.DecryptDocument(data)
        if err2 != nil {
            fatalf("decrypt: %v", err2)
        }
        result, err = box.UnsignDocument(plain)
        if err != nil {
            fatalf("unsign after decrypt: %v", err)
        }
    }
    content = result.Content

    if *verbose {
        for _, s := range result.Signers {
            if s.CertInfo != nil {
                fmt.Fprintf(os.Stderr, "signer: %s (%s)\n", s.CertInfo.CommonName, s.CertInfo.EDRPOU)
            }
            fmt.Fprintf(os.Stderr, "  valid=%v time=%v\n", s.Valid, s.SigningTime.Format(time.RFC3339))
            if s.Error != nil {
                fmt.Fprintf(os.Stderr, "  error: %v\n", s.Error)
            }
        }
    }

    mustWrite(*output, content)
}
```

### 5. Encrypt command (`cmd_encrypt.go`)

```
dstu encrypt [flags]
  -key path[:password]    Sender key container
  -cert path              Sender certificates (repeatable)
  -crypt path             Recipient certificate
  -input path             Input file
  -output path            Output file
```

```go
func runEncrypt(args []string) {
    fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
    key := fs.String("key", "", "key container path[:password]")
    var certs multiFlag
    fs.Var(&certs, "cert", "sender certificate (repeatable)")
    cryptCert := fs.String("crypt", "", "recipient certificate")
    input := fs.String("input", "-", "input file")
    output := fs.String("output", "-", "output file")
    fs.Parse(args)

    cf := commonFlags{keyFlag: *key, certFlags: certs}
    box, err := buildBox(cf)
    if err != nil {
        fatalf("setup: %v", err)
    }

    if *cryptCert == "" {
        fatalf("-crypt recipient certificate is required")
    }
    recipientDER := mustRead(*cryptCert)
    content := mustRead(*input)

    result, err := box.EncryptForRecipientDER(content, recipientDER)
    if err != nil {
        fatalf("encrypt: %v", err)
    }
    mustWrite(*output, result)
}
```

### 6. CertInfo command (`cmd_certinfo.go`)

```
dstu certinfo [flags]
  -cert path    Certificate file (.cer, .der, .pem)
  -json         Output as JSON
```

```go
func runCertInfo(args []string) {
    fs := flag.NewFlagSet("certinfo", flag.ExitOnError)
    certPath := fs.String("cert", "", "certificate file")
    asJSON := fs.Bool("json", false, "output as JSON")
    fs.Parse(args)

    if *certPath == "" && fs.NArg() > 0 {
        *certPath = fs.Arg(0)
    }
    if *certPath == "" {
        fatalf("-cert is required")
    }

    data := mustRead(*certPath)
    info, err := ua.GetCertInfo(data)
    if err != nil {
        fatalf("certinfo: %v", err)
    }

    if *asJSON {
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        enc.Encode(info)
        return
    }

    fmt.Printf("Subject:      %s\n", info.Subject)
    fmt.Printf("CommonName:   %s\n", info.CommonName)
    fmt.Printf("Organization: %s\n", info.Organization)
    fmt.Printf("Title:        %s\n", info.Title)
    fmt.Printf("EDRPOU:       %s\n", info.EDRPOU)
    fmt.Printf("DRFO:         %s\n", info.DRFO)
    fmt.Printf("Email:        %s\n", info.Email)
    fmt.Printf("Serial:       %s\n", info.Serial)
    fmt.Printf("NotBefore:    %s\n", info.NotBefore.Format(time.RFC3339))
    fmt.Printf("NotAfter:     %s\n", info.NotAfter.Format(time.RFC3339))
    fmt.Printf("Role:         %s\n", info.Role)
    fmt.Printf("Algorithm:    %s\n", info.Algorithm)
    fmt.Printf("Curve:        %s\n", info.CurveName)
    fmt.Printf("IsCA:         %v\n", info.IsCA)
}
```

### 7. Unprotect command (`cmd_unprotect.go`)

Remove password protection from a key container, writing the raw (unencrypted) private key.

```
dstu unprotect [flags]
  -key path:password    Encrypted key container
  -output path          Output file (default: stdout, PEM format)
  -der                  Output DER instead of PEM
```

```go
func runUnprotect(args []string) {
    fs := flag.NewFlagSet("unprotect", flag.ExitOnError)
    keyFlag := fs.String("key", "", "key container path:password")
    output := fs.String("output", "-", "output file")
    asDER := fs.Bool("der", false, "output DER instead of PEM")
    fs.Parse(args)

    parts := strings.SplitN(*keyFlag, ":", 2)
    if len(parts) != 2 {
        fatalf("-key must be path:password")
    }
    keyData := mustRead(parts[0])
    password := parts[1]

    priv, err := keystore.Parse(keyData, password)
    if err != nil {
        fatalf("load key: %v", err)
    }

    var out []byte
    if *asDER {
        out, err = keystore.MarshalPrivateKeyDER(priv)
    } else {
        out, err = keystore.MarshalPrivateKeyPEM(priv)
    }
    if err != nil {
        fatalf("marshal key: %v", err)
    }
    mustWrite(*output, out)
}
```

### 8. Write tests (`cmd/dstu/main_test.go`)

Integration tests using `os/exec` to run the compiled binary:

```go
func TestSign_NoTax_Roundtrip(t *testing.T) {
    // Write test content to temp file
    // Run: dstu sign -key testkey -cert testcert -input content -output sig --no-tax
    // Run: dstu decrypt -key testkey -input sig -output recovered
    // Assert recovered == original content
}

func TestCertInfo_Fields(t *testing.T) {
    // Run: dstu certinfo -cert testcert.cer
    // Parse stdout, assert CommonName, EDRPOU, etc.
}

func TestCertInfo_JSON(t *testing.T) {
    // Run: dstu certinfo -cert testcert.cer -json
    // Parse JSON output
}
```

---

## ua package additions needed

The CLI requires a few thin helpers on `ua.Box` that may not exist yet:

| Method | Purpose |
|--------|---------|
| `box.SignAndEncryptFile(content, recipientDER, opts)` | Accept raw recipient cert DER instead of parsed cert |
| `box.EncryptForRecipientDER(content, recipientDER)` | Thin wrapper parsing cert then calling `EncryptDocument` |
| `ua.GetCertInfo(der)` | Already exists |

If these aren't present, add them in `ua/box.go` as one-liner wrappers.

Also add to `keystore`:

| Function | Purpose |
|----------|---------|
| `keystore.MarshalPrivateKeyDER(priv)` | Serialize `dstu4145.PrivateKey` to raw PKCS#8 DER |
| `keystore.MarshalPrivateKeyPEM(priv)` | Serialize to PEM |

---

## Acceptance Criteria
- [ ] `dstu sign -key k -cert c -input f -output f.p7s --no-tax` produces a valid CMS file verifiable at `czo.gov.ua/verify`
- [ ] `dstu sign -key k -cert c -input f -output f.enc -crypt r.cer` produces transport container (sign+encrypt)
- [ ] `dstu decrypt -key k -input f.p7s -output clear` recovers original content
- [ ] `dstu decrypt -key k -ca ca.p7b -input f.p7s -v` prints signer info to stderr
- [ ] `dstu encrypt -key k -cert c -crypt r.cer -input f -output f.enc` produces CMS EnvelopedData
- [ ] `dstu certinfo -cert c.cer` prints all Ukrainian-specific fields
- [ ] `dstu certinfo -cert c.cer -json` outputs valid JSON
- [ ] `dstu unprotect -key Key-6.dat:password -output key.pem` writes PEM private key
- [ ] `dstu unprotect -key Key-6.dat:password -der -output key.der` writes DER
- [ ] stdin/stdout work when `-input -` or `-output -`
- [ ] All existing tests still pass after ua/keystore additions

## Notes
- Use `flag.FlagSet` per subcommand for clean `--help` output per command
- Pipe support (stdin/stdout) makes the tool scriptable and compatible with shell pipelines
- The `--role` flag maps directly to `cert.Role` for JKS multi-key stores
- Filename format for tax office transport headers follows the agent README convention
- Do **not** implement the agent IPC/socket mode — that is out of scope
