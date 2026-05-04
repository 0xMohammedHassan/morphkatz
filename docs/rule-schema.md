# MorphKatz rule schema (YAML, v1.0)

MorphKatz rule packs live under `rules/x64/` as YAML documents. A pack is
a single file containing a top-level `rules:` list. Every list entry is
one rule that the loader (`src/rules/rule_loader.cpp`) compiles into a
predicate plus a rewrite template.

Two rule flavours coexist:

1. **Per-instruction rewrites** — the matcher walks the decoded CFG and
   applies a rule when `match:` matches a single instruction. The rule
   supplies a typed rewrite template under `rewrite:`; the encoder
   (`src/engine/encoder.cpp`) produces the replacement bytes.
2. **Raw-byte rules** — bypasses the per-instruction matcher. The
   orchestrator feeds `(raw_from, raw_to)` pairs into `Patcher::queue_raw`,
   which runs them through an Aho-Corasick automaton over executable
   sections.

---

## Schema reference

```yaml
id: <string>            # required. Globally unique rule id, e.g. "x64.zero.xor_to_sub".
description: <string>   # optional. Human-readable summary.
weight: <double>        # optional. Selection weight (default 1.0).
flags_effect: <enum>    # optional. One of: equivalent | equivalent_if_dead | not_verified.
                        # Defaults to equivalent.
size_delta: <int>       # optional. Expected byte-length delta; -1 for variable.
                        # Default 0.

# --- Per-instruction match (mutually exclusive with `raw:` block) ---
match:
  mnemonic: <string>    # Intel mnemonic, e.g. XOR, MOV, ADD, CMP, TEST.
  operand_count: <int>  # optional. Default: any.
  constraints:          # optional list.
    - op_index: <int>
      kind: any | register | immediate | memory | relative
      reg_class: any | gpr | gpr8 | gpr16 | gpr32 | gpr64 | xmm | ymm | zmm
      imm_equals: <int>             # optional
      size_bits: <int>              # optional (8/16/32/64)
  same_register:                     # optional, list of paired operand indices
    - [0, 1]
  register_blacklist:                # optional
    - RSP
    - RBP

rewrite:
  mnemonic: <string>
  operands:
    - source: copy_from | immediate | register
      copy_from_op: <int>      # when source == copy_from
      imm_value: <int>         # when source == immediate
      imm_size_bits: <int>     # when source == immediate
      reg: <string>            # when source == register
      size_bits: <int>         # optional override

# --- Raw-byte match (mutually exclusive with `match:`) ---
raw:
  from:  [0x48, 0x31, 0xC0]     # bytes to locate
  to:    [0x48, 0x29, 0xC0]     # replacement (must be same length)
```

### `flags_effect` semantics

| value               | meaning                                                                                             |
|---------------------|-----------------------------------------------------------------------------------------------------|
| `equivalent`        | Rewrite's flag effect is byte-identical to the source after canonicalisation (see `decoder.cpp`).  |
| `equivalent_if_dead`| Rewrite changes some flag bits; only applied when every differing bit is dead at this instruction. |
| `not_verified`      | Rule author opts out; the matcher emits a WARN log on every match. Use sparingly.                   |

Flag-liveness dataflow (`src/analysis/flag_liveness.cpp`) drives the
`equivalent_if_dead` gate at `src/rules/rule_matcher.cpp`.

### Rewrite operand sources

- `copy_from` — take the operand from the source instruction at index
  `copy_from_op`. Used for register, immediate, and memory operands
  that the matcher already validated.
- `immediate` — emit an immediate with `imm_value` and
  `imm_size_bits`. For example, `CMP R, 0` is expressed as
  `copy_from_op: 0` for the register and `immediate 0` for the RHS.
- `register` — emit a specific register (`reg: RAX`).

### Raw rules — caveats

Raw rules *must* have identical `from`/`to` lengths (the patcher
enforces this and skips mismatched pairs with a warning). They match
**the entire executable section**, so they are appropriate only for
multi-byte signatures that are statistically unique inside real PEs
(e.g. Mimikatz's `48 8B 02 48 89 41 40` prologue). One-byte or
two-byte `from:` patterns will create collateral damage.

---

## Loader behaviour

- Files are parsed recursively from `--rules-dir` (defaulting to the
  `share/morphkatz/rules` install dir) plus every `--extra-rules` path.
- Parse errors are fatal: a single malformed YAML aborts the load.
- Duplicate `id:` values across files are rejected.
- Unknown keys emit a WARN but do not abort.

## Profile gating

`--profile safe|normal|aggressive` filters rules by tag. A rule with no
tag participates in every profile. The tag set is currently minimal and
documented in `src/rules/rule_loader.cpp`.

## Writing a new rule

1. Pick the right directory:
   - `rules/x64/equivalence/` — semantically equivalent rewrites.
   - `rules/x64/encoding/` — alternate encoding forms of the same
     semantics (MOV 89/8B swap, AND/OR bit-fiddling).
   - `rules/x64/targeted/` — raw-byte patterns against a specific
     attacker toolchain (Mimikatz, CobaltStrike, Donut, Adaptix).
2. Keep `flags_effect: equivalent` where possible; the canonicaliser
   in `src/disasm/decoder.cpp` normalises the common zeroing and
   identity idioms so strict equivalence matches bit-for-bit.
3. Add a golden test: extend
   `tests/integration/targeted_byte_pairs_test.cpp` for a
   raw-byte rule, or add a new Catch2 unit test under
   `tests/unit/`.

---

Last updated: v1.0.
