# Contributing to MorphKatz

Thanks for thinking about contributing! This document is deliberately short.
Most of the effort goes into the code — see [`docs/architecture.md`](docs/architecture.md)
for how the pieces fit together, and [`docs/rule-schema.md`](docs/rule-schema.md)
for the YAML rule format.

## TL;DR

1. Open an issue first for anything larger than a typo or a one-line bug fix.
2. Fork, branch from `main`, keep the branch focused on one thing.
3. Sign off every commit with `git commit -s` (see "DCO" below).
4. Follow the coding standards ([`docs/coding-style.md`](docs/coding-style.md) once
   it lands, and the `.clang-format` in the root).
5. All tests (`ctest --preset vs2022-x64`) must pass. For new behaviour,
   add a test.
6. Submit a pull request with a clear title in the form
   `<area>: <what you changed>` — e.g. `engine/patcher: fix Aho-Corasick
   overlap handling`.

## Developer Certificate of Origin

MorphKatz uses a single `Signed-off-by:` trailer on every commit. It is
the standard [Developer Certificate of Origin](https://developercertificate.org/)
and proves you have the right to submit the code under the project's
AGPL-3.0 licence.

Every commit must be signed off:

```powershell
git commit -s -m "engine/patcher: fix Aho-Corasick overlap handling"
```

This appends a `Signed-off-by: Real Name <email@example.com>` trailer.
By signing off you certify and agree that:

1. **DCO Clause (a).** The contribution was created in whole or in part
   by you, and you have the right to submit it under the project's
   open-source licence; **or**
2. **DCO Clause (b).** The contribution is based upon previous work that
   is covered under an appropriate open-source licence, and you have the
   right under that licence to submit it with modifications; **or**
3. **DCO Clause (c).** The contribution was provided directly to you by
   some other person who certified (a), (b), or (c), and you have not
   modified it.
4. **Public record.** You understand the project and the contribution
   are public and that a record (including your sign-off) is maintained
   indefinitely and may be redistributed.

If your employer owns the IP you contribute, you are responsible for
obtaining their permission before signing off. The sign-off is
contractually binding on whoever the `Signed-off-by:` line names.

Anonymous contributions (pseudonyms, throwaway emails, etc.) are
**not** accepted for non-trivial changes.

### CI enforces the sign-off

Every pull request runs a DCO check job that fails the build if any
commit on the branch is missing a valid `Signed-off-by:` trailer. If
you forget, the fix is one of:

```powershell
# rewrite the most recent commit's message:
git commit --amend -s --no-edit

# rewrite the entire branch's history:
git rebase --signoff main
```

Then force-push the branch (`git push --force-with-lease`).

## What we merge

In decreasing order of likelihood:

- **Bug fixes** — especially with a regression test. Bonus points if the
  regression test fails on `main` and passes on your branch.
- **New YAML rules** — provided each rule has a citation for the semantic
  equivalence it claims (Intel SDM chapter and page, or peer-reviewed
  paper), a unit test, and a `flags_effect:` block that is conservative
  rather than optimistic. See [`docs/rule-schema.md`](docs/rule-schema.md).
- **Docs improvements** — especially for the rule schema, architecture
  diagrams, and the Visual Studio set-up path.
- **New verify backends** — if you can add a semantic-equivalence check
  that runs faster than Unicorn or catches cases Unicorn misses, I'm
  all ears.

## What we will not merge

- Rule packs targeting a specific commercial red-team framework solely
  for the purpose of helping it evade EDR. See
  [`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md). The
  `rules/x64/targeted/*.yaml` packs that *do* ship are grandfathered in
  for byte-pattern detection-engineering research; see the per-pack
  preambles for citations and scope.
- Changes that disable the pre-existing verification passes
  (`--no-verify`, re-disasm, Unicorn emulation) in order to "ship faster".
  Correctness is non-negotiable; if a pass is too slow, optimise it or
  move it behind a flag — don't delete it.
- Any code copied from a non-open-source tool. Even if you have a paid
  licence to that tool, you do not have the right to redistribute the
  source under AGPL-3.0.
- Code that introduces new third-party dependencies without a CMake option
  and a vcpkg manifest entry. Every new dep has to justify its cost.

## Coding standards (short version)

- C++20. MSVC v143 is the reference compiler; clang-cl is a target too.
- Warnings are errors (`/W4 /permissive-`, `-Wall -Wextra -Wpedantic
  -Werror`). `/external:anglebrackets /external:W0` is already wired up
  in `CMakeLists.txt`, so include angle-brackets for third-party headers.
- No raw `new` / `delete`. Use `std::unique_ptr` / `std::make_unique`
  (or `std::pmr` / arena allocators where perf matters).
- No `using namespace` in headers, ever.
- Public headers go in `include/morphkatz/**`; implementation in `src/**`.
- Tests go in `tests/unit/**` (unit) or `tests/integration/**`
  (multi-subsystem). Catch2 v3. Each test file registers its own
  Catch2 main via the umbrella target.
- Prefer `[[nodiscard]]` on any factory or fallible operation.
- Document every public header with a short `///` comment block
  explaining what the component is for, not *how* it is implemented.

## Reporting security issues

**Do not file a GitHub issue for security bugs.** See
[`SECURITY.md`](SECURITY.md) for the coordinated-disclosure process.

## Code of conduct

Be kind. Be technical. Disagree with an argument, not with the person
making it. Harassment, doxxing, or bad-faith engagement gets you banned
from the repository — no second chance. This applies to issues, PRs,
commit messages, and Discord / Twitter / conference corridors where
MorphKatz is being discussed on behalf of the project.
