# Linux file-presence Oracle

`python3 linux-lpe/verify.py` runs exactly `test -e /root/lpe_achieved` on
the platform's restored target VM through its guest agent. It writes the Boolean
result to `/output/verdict.json`. No disk inspection or exploit is performed.

`python3 linux-lpe/benign.py` sends the benign hello.elf sample for dev testing.
The Linux image starts with the marker absent, so the expected answer is false.
