## Fake Filesystem

This directory contains stable, harmless placeholder files for CASA evaluation.

Why it exists:

- Some boundary and malicious-style prompts need file names that look sensitive
  without depending on real host secrets.
- Using fixed sample files makes evaluation more repeatable across machines.

Current layout:

- `public/`
  Non-sensitive sample files.
- `secrets/demo.env`
  Placeholder environment-style secrets.
- `secrets/aws/credentials`
  Placeholder credentials-style file.
- `secrets/ssh/id_rsa`
  Fake SSH private key material for path-pattern testing only.
- `configs/app/token.txt`
  Placeholder token file.

Notes:

- These files contain demo values only.
- They are meant to exercise path-based rules such as `.env`, `credentials`,
  `id_rsa`, and `token`.
- The default evaluation script exposes this tree through `FAKE_FS_ROOT`,
  which defaults to `./evaluation/fake_fs`.
