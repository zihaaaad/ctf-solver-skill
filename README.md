# CTF Solver Skill

A portable, field-tested skill for solving Capture-The-Flag challenges from a
Linux command line. It gives an AI coding agent (or a human operator) a clear
triage flow, per-category playbooks, verification discipline, and a list of
common failure modes.

The skill is written as a single self-contained `SKILL.md` with standard
frontmatter, so it can be installed into Claude Code / Claude agents or simply
read as an operator checklist.

## What it covers

- Pwn (remote binary exploitation) and reverse engineering
- Cryptography (encoding chains, classical and modern schemes, lattice, keystream analysis)
- Web exploitation
- Forensics (disk images, Windows artifacts, memory)
- Steganography (image, audio, space-filling-curve, visual ciphers)
- Network / pcap analysis
- OSINT and miscellaneous puzzles
- Shared-state tracking and safe submission under attempt limits

## Repository layout

```
.
├── README.md
├── LICENSE
└── skills/
    └── ctf-solver/
        └── SKILL.md
```

## Installation

### Claude Code / Claude agents

Copy the skill directory into your personal skills folder:

```bash
git clone https://github.com/zihaaaad/ctf-solver-skill.git
mkdir -p ~/.claude/skills
cp -r ctf-solver-skill/skills/ctf-solver ~/.claude/skills/
```

The agent will load it automatically when a task matches the triggers in the
skill description (a CTF challenge, a challenge artifact, or a lab target).

To use it inside a Claude Code plugin instead, place `skills/ctf-solver` under
your plugin's `skills/` directory.

### Human operators

Open `skills/ctf-solver/SKILL.md` and follow Section 1 (rapid triage) to route to
the correct playbook. The document is designed to be read top to bottom once, then
used as a reference.

## Recommended tooling

The skill assumes a Parrot OS or Kali-style environment with, among others:
`python3` (pwntools, pycryptodome, PIL, numpy, sympy), `gdb`, `ghidra` or
`radare2`, `sleuthkit`, `ewfmount`, `tshark`, `zsteg`, `binwalk`, `steghide`,
`curl`, `sqlmap`, `ffuf`, `patchelf`, and `docker`.

## Scope and responsible use

This material is for authorized security testing, CTF competitions, and
education only. Use it exclusively against systems you own or are explicitly
permitted to test. The authors accept no liability for misuse.

## License

Released under the MIT License. See [LICENSE](LICENSE).
