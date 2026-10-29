# EncryptedArticles fixtures (vendored copy)

Copies of the tamper/placement wire articles vendored under
`tests/NzbWebDAV.Tests/TestFixtures/EncryptedArticles/` (manifest there),
duplicated here so `YencVectorTests` can exercise production
`YencControlRestorer.Restore` without reaching outside this test project.
Phase 3 adds the article/expected-plaintext set (article-single/part1/part2,
expected-single/multipart) so the pump/YencStream tests in `Encryption/`
(`EncryptedPumpTests`, `EncryptedLoopbackTests`, `EncryptedBeforeKdfTests`)
load fixtures from this project's own output directory.
Generated once with the standards Python reference; tests must never
encrypt fixtures with production crypto. No hash/byte-equality gate
between the two copies (settled helpers rule) — refresh by hand if the
source fixtures are regenerated.
`tamper-tag.bin` (parsed-field tag tamper: salt/index agree, one tag byte
flipped) was added the same way — see the manifest in the NzbWebDAV.Tests
copy for the generation command (`/tmp/opencode/gen_tamper_tag.py`).
