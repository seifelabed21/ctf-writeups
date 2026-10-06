# 🕵️ Securinets CTF Friendly 2026 — Short Fuse

> **Category:** Pwn — Format String  
> **Difficulty:** Medium  
> **Points:** 295  
> **Author:** Taz  
> **Flag:** `Securinets{f1v3_ch4rs_w4s_4ll_1t_t00k}`

---

# 🌌 ERA I — Pwn

In the Pwn era, a program is not just a tool to run; it is a machine whose state can be influenced through memory. A small mistake in how input is handled can become a leak, a write, or control-flow redirection.

Format-string bugs are especially instructive because the attacker does not need a large overflow. The format language itself becomes a memory-access interface: conversions can disclose values, and `%n` can write the number of bytes printed through a pointer argument.

This episode combines that primitive with an unusual length check, a self-overlapping `sprintf`, the GOT, and the matching libc. The mindset is to model the actual bytes at each stage—not just the visible input—and to use small writes to turn one bug into a full execution chain.

---

# 📺 EPISODE 01 — Short Fuse

## 🎬 The Briefing

**Challenge description:**

> Rootstar's debug console only lets you type five characters before it cuts the line.  
> Light the fuse fast enough and even printf can't save it from itself.

### 🗺️ Mission

**Objective:** Use the format-string flaw to redirect execution and print the flag from the remote service.

**Given:**

- `main(4)`, the x86-64 challenge binary
- The matching challenge `libc.so.6` and loader
- Remote service

**Target:**

```text
pwn.friendly-ctf.securinets.tn:9060
```

---

# 🧩 Scene 1 — First Contact

```bash
nc pwn.friendly-ctf.securinets.tn 9060
```

The service begins with:

```text
Let's see the diff between printf and puts
```

It then waits for the single input consumed by the vulnerable function.

### 👀 What do we notice?

- The binary imports both `printf` and `puts`, foreshadowing a difference in how input is treated.
- There is a very small input-length check, but the actual read is much larger.
- The program has a challenge-local `flag` path and a `puts` call after the formatted output.

### 🧠 First Hypothesis

> The five-character guard may be bypassable if it measures a C string rather than the number of bytes read; after that, the input may be interpreted as a format string.

The key questions are whether the length check can be evaded, where the format string lands after `sprintf`, and whether the variadic argument area contains pointers we can control.

---

# 🔬 Scene 2 — Examining the Evidence

## 📦 Step 1 — Identify the Target

```bash
file 'main(4)'
readelf -h 'main(4)' | grep Type
readelf -l 'main(4)' | grep -E 'GNU_STACK|GNU_RELRO' -A1
nm -n 'main(4)' | grep -E ' (vuln|main)$'
```

Key results:

```text
ELF 64-bit LSB executable, x86-64
Type: EXEC (Executable file)
vuln: 0x401202
main: 0x4012c2
GNU_STACK: RW (non-executable stack)
GNU_RELRO: present, but GOT remains writable (partial RELRO)
```

### What does this tell us?

| Finding | Meaning | Why it matters |
|---|---|---|
| Non-PIE (`ET_EXEC`) | Main executable addresses are fixed | The GOT and `main` addresses can be used directly |
| NX stack | Stack bytes cannot be executed | We use libc/system and a GOT redirection, not stack shellcode |
| Canary in `vuln` | A stack canary is checked on return | The exploit avoids overflowing to the canary |
| Partial RELRO | PLT/GOT entries are writable at runtime | `puts@GOT` and `exit@GOT` can be changed |

---

# 🧠 Scene 3 — Understanding the Program

## 📖 Reading the Source

The relevant control flow recovered from the disassembly is equivalent to:

```c
void setup(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
    open("flag", O_RDONLY);   // return value is not used here
}

void vuln(void) {
    char buf[0x200];
    read(0, buf, 0x1ff);
    if (strlen(buf) > 5)
        exit(0);
    sprintf(buf, "Your text : %s ", buf);
    printf(buf);               // format-string vulnerability
    puts(buf);
}

int main(void) {
    setup();
    vuln();
    exit(0);
}
```

### 🔎 The suspicious part

```c
read(0, buf, 0x1ff);
if (strlen(buf) > 5) exit(0);
sprintf(buf, "Your text : %s ", buf);
printf(buf);
```

1. `read` does not append a terminator; the input can contain its own NUL byte.
2. `strlen` stops at the first NUL, so a leading NUL makes the measured length zero.
3. `sprintf` uses the same buffer as both destination and `%s` source. This overlap is undefined in portable C, but the supplied glibc's observed behavior leaves the input format text after the generated prefix.
4. `printf(buf)` interprets the surviving percent sequences instead of printing them literally.

### What the program thinks is happening

```text
Read at most 511 bytes
    ↓
Check a short C-string length
    ↓
Add a friendly prefix
    ↓
Print the result
```

### What is actually happening

```text
Input begins with NUL
    ↓
strlen returns 0, regardless of later bytes
    ↓
%s copies the overlapping input behind "Your text : "
    ↓
printf parses attacker-controlled conversions
    ↓
Leak / byte-write primitive
```

---

# 💥 Scene 4 — Finding the Vulnerability

## 🚨 Vulnerability

**Type:** Format-string vulnerability with a NUL-based length-check bypass and positional `%hhn` writes.

### The root cause

The program passes attacker-controlled data as the *format argument* to `printf`. The `strlen` guard does not measure the full read; it measures only bytes up to the first NUL. The overlapping `sprintf` then preserves the later format text in the output buffer.

### Why is it exploitable?

1. Put a NUL at the first byte so `strlen(buf) == 0`.
2. Put padding and a format string after it; this is not counted by `strlen`.
3. Put pointer values later in the same buffer, at an offset that maps to variadic stack slots.
4. Use `%hhn` to write one byte at a time to chosen GOT addresses.
5. Change `exit@GOT` to `main` temporarily to obtain multiple input rounds, leak libc addresses, then change `puts@GOT` to `system`.

### The primitive

> **A constrained, byte-at-a-time arbitrary write through `%hhn`, plus libc pointer leaks through `%s`.**

This lets us alter a future function call without touching the canary or return address.

---

# 🧪 Scene 5 — Experimentation

### Experiment #1 — Ordinary input

A short harmless string passes the guard, and the program prints its fixed prefix. This confirms the service is a one-input process and exposes the format stage after the prefix.

### Experiment #2 — NUL-prefixed format

The payload begins with `\x00`, followed by filler, format directives, and pointer words at buffer offset `0x100`. Positional probing confirms that the first appended pointer is reachable as argument 38; subsequent words occupy 39, 40, and so on.

Example format fragment:

```text
%1$170c%38$hhn%1$80c%39$hhn
```

### What did we learn?

- The hard-coded prefix contributes 24 printed characters before the format conversion runs.
- `%hhn` writes the current character count modulo 256.
- Appending target addresses beyond the format string gives the format directives controlled pointers to dereference.

---

# 🧭 Scene 6 — The Turning Point

At this point, we know:

- The NUL bypass defeats the five-character check.
- The GOT is writable and the executable has fixed addresses.
- Replacing `exit@GOT` lets the same process return to `main` for another round.

But we still need the runtime libc base; ASLR changes it on each connection.

The key question becomes:

> **Can we leak a resolved libc function pointer and reuse the same live process to install the correct `system` address?**

### 💡 The breakthrough

The GOT entries for `puts`, `printf`, `read`, and `open` contain resolved libc addresses by the time the vulnerable `printf` runs. We can print those pointer bytes with `%s`, use the supplied libc's symbol offsets to calculate its base, and then write the runtime `system` address to `puts@GOT`.

---

# 🧠 Scene 7 — Building the Exploit

## 🎯 Exploit Strategy

```text
NUL-prefixed input bypasses strlen
      ↓
Round 1: write main into exit@GOT
      ↓
Round 2: leak libc GOT entries and re-arm exit@GOT
      ↓
Compute libc base from a leaked symbol
      ↓
Round 3: write system into puts@GOT
      ↓
puts(buf) becomes system(buf)
      ↓
Append ;cat flag and capture the flag
```

## 🔧 Step 1 — Re-enter `main`

Write the six low address bytes of `main` (`0x4012c2`) to `exit@GOT` (`0x404040`) using `%hhn`. High canonical bytes are already zero.

### Why does this work?

After `vuln` returns, `main` calls `exit(0)`. The patched PLT entry instead re-enters `main` and provides another chance to supply a payload in the same process.

## 🔧 Step 2 — Leak libc

Write `main` to `exit@GOT` again, then use `%s` through controlled stack pointers to print the resolved GOT entries. The uploaded matching libc provides symbol offsets; alternatively, the helper can query libc.rip.

### Why does this work?

All leaked addresses belong to the same libc mapping in the current process. Subtracting a known symbol offset yields the page-aligned libc base.

## 🔧 Step 3 — Turn `puts` into `system`

Write the runtime `system` address to `puts@GOT` (`0x404000`) and end the format text with `;cat flag`.

### Why does this work?

After `printf` returns, the binary calls `puts(buf)`. With the GOT entry changed, the call dispatches to `system(buf)`. The semicolon starts the `cat flag` command even if the prefixed text before it is treated as a failed shell command.

---

# 🧬 Scene 8 — The Final Exploit

The reusable three-round runner is available as [the tested Short Fuse exploit script](short_fuse_exploit.py). Its core write builder is:

```python
def byte_writes(target, value, start_count, first_arg, count=6):
    fmt, pointers, printed = bytearray(), [], start_count
    for i, byte in enumerate(value.to_bytes(8, "little")[:count]):
        pointers.append(target + i)
        pad = (byte - printed) & 0xff
        if pad:
            fmt += f"%1${pad}c".encode()
            printed += pad
        fmt += f"%{first_arg + i}$hhn".encode()
    return bytes(fmt), pointers

# The user's leading NUL bypasses strlen; format starts at input offset 12.
# The first controlled pointer is placed at offset 0x100 (argument 38).
```

The full runner handles the 3 input rounds, GOT leaks, local-libc offsets, socket reads, and final flag output.

### Exploit walkthrough

| Code / function | Purpose |
|---|---|
| `payload_with_format` | Adds the NUL, padding, format, and appended pointers |
| `retarget_main_payload` | Sends `exit@GOT → main` byte writes |
| `leak_and_retarget_payload` | Repeats the loop redirection and reads GOT pointers |
| `final_payload` | Installs `system` in `puts@GOT` and appends `;cat flag` |

---

# 🏁 Scene 9 — The Final Confrontation

```bash
python3 short_fuse_exploit.py --libc ./libc.so.6
```

The live service returned:

```text
Securinets{f1v3_ch4rs_w4s_4ll_1t_t00k}
```

> _The five-character fuse was only a check on the first C string—not on the bytes the process actually read._

---

# 🧠 Post-Mission Analysis

## 🔑 What was the actual vulnerability?

A format string passed directly to `printf`, reached through a NUL-byte bypass of a `strlen` limit. The input/output overlap in `sprintf` preserves the format string after the generated prefix on the challenge's runtime.

## 🎯 What was the intended exploitation path?

Use positional `%hhn` writes to loop back to `main`, leak libc addresses, calculate `system`, replace `puts@GOT`, and execute a command through the final `puts(buf)` call.

## 🧰 Important techniques

- **NUL length-check bypass** — `strlen` stops before the uncounted payload.
- **Positional format-string writes** — `%hhn` changes one GOT byte at a time.
- **GOT redirection and libc-base calculation** — turn an existing call into `system` under ASLR.

## 🧩 The mental model

```text
NUL bypass
    ↓
Format-string leak/write
    ↓
GOT control
    ↓
Libc base and system address
    ↓
puts → system
    ↓
cat flag
```

---

# 🧪 What I Learned

### Before the challenge

> A small input cap seems to rule out a useful format string.

### During the challenge

> The cap measured a C string, while the vulnerable code processed a larger buffer—and then reused it as its own format string.

### After the challenge

> Format-string bugs can be staged: first gain repeatable input, then disclose addresses, then perform the final write.

### The lesson

> **A length check is only as strong as the representation it measures.**

---

# 📚 Concepts Worth Reviewing

- C strings, embedded NUL bytes, and `read` versus string length
- `printf` conversions, positional arguments, `%s`, and `%hhn`
- ELF PLT/GOT, RELRO, and ASLR
- Deriving libc bases from leaked function addresses

### Recommended learning order

```text
C strings and variadic functions
     ↓
Format-string reads and writes
     ↓
ELF GOT/PLT and ASLR
     ↓
Short Fuse
```

---

# 🗂️ Investigation Summary

| Phase | What happened |
|---|---|
| **Recon** | Identified a short length check followed by `sprintf` and `printf` |
| **Analysis** | Confirmed a leading NUL bypass and fixed executable/GOT addresses |
| **Vulnerability** | Attacker-controlled format string, with overlapping buffer behavior |
| **Primitive** | GOT leaks and arbitrary byte writes through `%hhn` |
| **Strategy** | Loop through `main`, derive libc base, replace `puts` with `system` |
| **Exploitation** | `system(buf)` executed `;cat flag` |
| **Flag** | `Securinets{f1v3_ch4rs_w4s_4ll_1t_t00k}` |

---

# 🎬 END OF EPISODE

> **Episode 01 — Short Fuse**  
> **Status:** ✅ Solved  
> **Category:** Pwn  
> **Difficulty:** Medium  
> 
> _The case is closed._
> 
> _For now._

---

# 🔮 NEXT EPISODE

> **Next challenge:** `2nd Download`  
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
