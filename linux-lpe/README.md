# Linux LPE marker example

The frozen Linux image starts with `/root/lpe_achieved` absent. The Oracle reads
the original saved disk and returns true only for a regular file at that path.

```sh
python3 linux-lpe/verify.py --contract linux-lpe/contract.json
```

`python3 linux-lpe/benign.py` sends the benign hello.elf sample for local dev
rehearsal. It is expected to produce a completed false Oracle verdict.
The sample prints hello and makes no attempt to create the root marker.
No exploit is included. Python 3, qemu-img and e2fsprogs are required by the Oracle.
