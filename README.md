# Deterministic exchange-flag Oracle

This repository contains a single-file, Python-standard-library verifier for the
`linux-lpe` frozen flag-recovery challenge. `verify.py` is generated from the
reviewed engine and CLI; it performs no network, target, guest-agent, subprocess,
or service calls. The trusted `contracts/linux-lpe.json` binds the image
SHA-256, target ID and exposed TCP ports. It must be frozen at publication.

```sh
python3 verify.py --contract contracts/linux-lpe.json \
  --manifest /input/manifest.json --pcap /input/traffic.pcap \
  --output /output/verdict.json
```

A valid capture that does not satisfy the protocol writes a Boolean `false`
verdict and exits 0. Missing/misbound evidence (including a wrong image hash,
forwarded-port declaration, traffic hash, or malformed PCAP transport profile)
exits 2 without a verdict; the platform must treat that as unavailable/null, not
NO. The verifier never reads a guest file or the token itself.

Contract SHA-256: `511f3a8d31a1a9a1980c8b99a11b4573303fa0a039bc05593f550d6258405c27`  
Verifier SHA-256: `7517b931745c2e01c1d646d441fddad4f85deb45e3605e0a6958b169cd5c8b47`

This is a frozen confidentiality/privilege challenge, not a claim that a
historical CVE is reproducible or unpatched. A YES proves captured knowledge of
the committed secret, not the particular code path that recovered it.
