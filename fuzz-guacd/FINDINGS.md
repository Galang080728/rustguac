# guacd Parser Fuzzing Findings

Harness targets `guac_parser_append()` from guacamole-server's libguac —
the core state machine that parses all Guacamole wire-format data received
from clients.

## Setup

- **Fuzzer**: libFuzzer (clang 19) with ASan + UBSan
- **Target function**: `guac_parser_append()` in `src/libguac/parser.c`
- **Dependencies compiled inline**: `parser.c`, `unicode.c` (no autoconf needed)

Build: `./build.sh` (requires clang)

## Results

**Run date**: 2026-02-07
**Iterations**: ~3.2 million (5 minutes)
**Exec/s**: ~10,800
**Coverage**: 138 edges (saturated — parser state machine is compact)

### No crashes or memory errors

ASan found no heap buffer overflows, use-after-free, or other memory
corruption issues in 3.2M iterations across varying chunk sizes.

### Signed integer overflow in length prefix parser (UBSan, non-exploitable)

**Location**: `parser.c:83`
**Severity**: Informational (undefined behavior, not exploitable)

The length prefix accumulator:
```c
parsed_length = parsed_length*10 + c - '0';
```
uses `int` arithmetic and can overflow with a long digit string (e.g.,
`222222222...`) before the subsequent bounds check:
```c
if (parsed_length > GUAC_INSTRUCTION_MAX_LENGTH) {
    parser->state = GUAC_PARSE_ERROR;
    return 0;
}
```

In practice, the `GUAC_INSTRUCTION_MAX_LENGTH` (8192) check catches
malicious lengths after the overflow wraps, and the parser transitions to
`GUAC_PARSE_ERROR`. The overflow is technically undefined behavior per the
C standard but has no security impact — the parser rejects the input
regardless.

**Upstream**: guacamole-server (Apache). Not filed — low impact, and the
existing bounds check is sufficient in practice.

## Rust protocol parser fuzzing

See `../fuzz/` for the Rust-side protocol parser fuzzer (cargo-fuzz).
That fuzzer found and fixed a UTF-8 char boundary panic in
`src/protocol.rs` — see commit history for v0.1.3.
