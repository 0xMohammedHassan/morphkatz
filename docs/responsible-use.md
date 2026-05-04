# Responsible use

MorphKatz is a *binary-rewriting research tool*. It produces polymorphic
variants of Windows x64 executables for the sole purpose of **defensive
research** — evaluating detection engines, testing YARA pack coverage,
and building datasets for academic work.

## What this project is for

- Red-team exercises authorised in writing by the system owner.
- Security-tool evaluation in labs you own or are contracted to test.
- Academic study of binary similarity, signature robustness, and
  equivalence-preserving rewrites.
- Tool-chain research: building better disassemblers, CFG algorithms,
  flag-aware dataflow passes.

## What this project is **not** for

- Bypassing anti-virus or EDR on systems you do not own or are not
  explicitly authorised to test.
- Evading detection as part of an actual intrusion.
- Distributing malware or obfuscating real-world attack payloads.

The author will refuse support requests that appear to originate from
offensive operations, and Pull Requests that ship rules targeting active
malware families will be closed without review.

## Ethical rule-pack contributions

When contributing rules (`rules/x64/**/*.yaml`) please avoid:

- Packs named after specific threat actors or commercial red-team tools
  whose primary purpose is to obscure detection.
- Rules derived solely from reverse-engineering a paid commercial AV/EDR
  signature database. Publish the *technique*, not the leaked vendor IP.

Do include:

- A citation for every instruction-level transformation (Intel SDM,
  AMD64 APM, peer-reviewed paper).
- A `flags_effect: equivalent` claim only when you have hand-verified
  both the arithmetic and the observable side effects.
- A unit test under `tests/unit/` (or extend
  `tests/integration/targeted_byte_pairs_test.cpp` for raw-byte
  rules) that exercises the new rule on a synthetic input.

## Legal

This project is licensed under the GNU Affero General Public License,
version 3.0 or later (AGPL-3.0-or-later) — see [`LICENSE`](../LICENSE)
for the full text. The licence grants you the right to use, study,
modify and redistribute the source (subject to AGPL's network-service
clause), but it does **not** grant authorisation to run the produced
binaries against third-party infrastructure. You remain solely
responsible for complying with:

- Your local computer-misuse laws (CFAA in the United States, Computer
  Misuse Act in the United Kingdom, §202c StGB in Germany, and so on).
- Contracts, NDAs and rules-of-engagement for any assessment you perform.
- Platform and distribution terms (Microsoft Store, Scoop, Chocolatey)
  when redistributing binaries.

When in doubt, don't.
