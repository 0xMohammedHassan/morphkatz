# MorphKatz trademark policy

"MorphKatz", the three-cat-heads-one-body logo (`assets/morphkatz-logo.png`),
and the tagline "N faces, one body" are **unregistered trademarks** of the
MorphKatz project maintainers. Common-law trademark protection applies in
jurisdictions where the project is in active use.

This document describes how you may — and may not — use those marks.

## You may

Without asking permission, you may:

- **Refer to MorphKatz** in articles, blog posts, conference talks,
  research papers, training material, and academic citations. Standard
  fair-use applies. Please do not imply endorsement.
- **Distribute unmodified source builds** under the AGPL-3.0 licence
  using the MorphKatz name, provided you are redistributing the actual
  MorphKatz code without modifications.
- **Display the logo** in slide decks, blog posts, READMEs of projects
  that integrate with MorphKatz, and other editorial contexts. Please
  link back to https://github.com/0xMohammedHassan/morphkatz.
- **Build products and services on top of MorphKatz** under the
  AGPL-3.0 licence. The trademark policy does not restrict your right
  to *use* the software — only to use the *name* and *logo*.

## You may not

Without prior written permission you may **not**:

- **Distribute modified MorphKatz builds** under the MorphKatz name.
  If you fork and modify the code, please rename the fork — e.g.
  "MorphKitten", "MyOrg-Morpher", "PolyShark". The renamed fork is of
  course free to mention "based on MorphKatz" in its README.
- **Sell a product, SaaS, or hosted service called "MorphKatz"** or
  any name confusingly similar (e.g. "MorphKats", "MorphKatzPro",
  "Katzmorph") in a way that suggests it is the official project.
- **Use the logo or name** in a way that suggests the MorphKatz
  maintainers endorse, sponsor, or are affiliated with your product
  without an actual endorsement agreement.
- **Register "MorphKatz" or substantially-similar names** as
  trademarks, domain names (TLDs other than what we already hold),
  app-store identifiers, social-media handles, GitHub-organisation
  names, package-registry names (npm, PyPI, NuGet, Cargo, vcpkg, etc.),
  or otherwise attempt to capture brand equity that belongs to the
  project.

## Forks

Friendly forks are welcome. The simplest pattern that respects this
policy:

1. Fork the GitHub repository.
2. Change the name in your fork's README, package metadata, and CLI
   help output.
3. Replace `assets/morphkatz-logo.png` with your own logo (or remove
   it).
4. Keep `LICENSE`, `CONTRIBUTING.md`, and the original copyright
   headers on the files you derived from us. AGPL-3.0 requires this
   anyway.
5. Optionally credit MorphKatz in your README with text like
   "Forked from [MorphKatz](https://github.com/0xMohammedHassan/morphkatz)".

You do **not** owe us anything beyond what AGPL-3.0 already requires.
The trademark policy only governs the *name* and *logo*, not the
code.

## Why a trademark policy on an OSS project?

A user installing something called "MorphKatz" has a reasonable
expectation that they're getting code maintained by the actual
project. Without trademark protection, anyone could ship malicious
binaries called "MorphKatz" and use the project's reputation as
cover. We've seen this happen to other security tools; it's not
theoretical.

This is not in tension with the OSS spirit. AGPL-3.0 plus a strong
trademark policy is the model adopted by Mozilla (Firefox),
Mattermost, and Plausible — robust OSS projects that protect their
name from impersonation while keeping the source code free.

## Permission requests

To request permission for any use not covered by "You may" above,
open a GitHub issue with the `trademark` label. We aim to reply
within 14 days. Permission is granted in writing and is specific to
the requested use.

## Reporting infringement

If you encounter a project, product, or service that misuses the
MorphKatz name, logo, or tagline, please open a GitHub issue. Most
disputes are resolved amicably with a polite rename request; we have
no interest in litigation as a first resort.
