# APK Gate

Blockchain quorum verification for Android apps.

An Android app is normally installed if it has a valid signature. But a valid signature only shows who signed the file, not how it was built. If a build server is hacked or a signing key is stolen, malware can still carry a valid signature.

APK Gate adds a second check. Several independent builders build the same app from the same source code and record the APK's digest in a smart contract. A device installs the APK only if:

1. the app is registered,
2. the signing certificate matches,
3. the release is not revoked,
4. the version is not below the minimum version, and
5. at least k of the n builders recorded the same digest.

The digest skips the APK Signing Block, so builders get the same value even though they do not hold the developer's signing key.

## Live demo

The web app runs the real compiled `ReleaseRegistry` contract on a private Ethereum chain inside the browser (using ethereumjs). No wallet, no test coins and no server are needed. You can drop in a real APK: the page reads the package name, version, signing schemes and certificate, and computes the digest locally. Nothing is uploaded.

The attack lab shows what happens when:

- a build server is hacked (one builder votes for a backdoored build),
- the signing key is stolen,
- an app is repackaged with injected code,
- an old version is installed (downgrade),
- a revoked release is installed,
- an outsider tries to vote.

## Repository layout

```
contract/   Solidity contract, Hardhat experiment script, Python digest tool, measured results
web/        Browser demo (src/ is the source, public/ is the deployable site)
diagrams/   Architecture and verification flow diagrams (draw.io)
```

## Run it

Contract experiments:

```
cd contract
npm install
npx hardhat compile
npx hardhat run scripts/experiment.js
python3 verifier/bench_digest.py
```

Web demo:

```
cd web
npm install
npm run build
# then serve web/public with any static server
```

## Results (local Hardhat network)

| Operation | Gas |
|---|---|
| Deploy contract | 756,689 |
| Register app, 3 builders | 163,213 |
| First vote for a digest | 72,262 |
| Next vote for the same digest | 55,162 |
| Revoke a release | 48,116 |
| Raise version floor | 29,119 |
| Verify | free (read-only) |

All 11 attack and access control scenarios gave the expected result (`contract/results/scenarios.json`).

On real Android test APKs, 33 APKs signed with v2 using 12 different keys all produced the same digest, and so did 22 APKs signed with v3 using 12 different keys. This shows the digest does not depend on who signed the file.

## Limits

- Needs reproducible builds. Many Android builds are not yet bit-for-bit reproducible.
- Built for APK Signature Scheme v2 or later. With v1 signing the signature files sit inside the ZIP.
- In this prototype, whoever registers a package name first becomes its owner. A real system needs proof of ownership.
- The repackaging demo simulates the certificate swap instead of re-signing the file in the browser.
- It does not catch harmful code that is committed into the source code itself.

## Credits

Jatin Kumar Singh, Department of Computer Science and Engineering, The NorthCap University, Gurugram.

The demo APK comes from the [androguard](https://github.com/androguard/androguard) test suite (Apache License 2.0).
