# AST Deobfuscation - Anti-Bots Like Bitshift | CTF Write-up

## Challenge Information

**Category:** Reverse Engineering / JavaScript / AST
**Challenge:** AST - Deobfuscation - anti-bots like bitshift

### Description

> *HessKamai has released version 2.0 of their anti-bot system. They believe nobody can reproduce the sensor generation anymore. Your friend sent you the AST—prove that their anti-bot is still reversible.*

---

# Initial Thoughts

At first glance, the challenge only provides a JSON file representing an **Abstract Syntax Tree (AST)**.

If you've never encountered ASTs before, they can look intimidating. They are essentially a structured representation of source code where every instruction is represented as a node in a tree instead of plain text.

For example, the JavaScript statement

```javascript
let x = 5 + 3;
```

can be represented as something like

```
VariableDeclaration
└── VariableDeclarator
    ├── Identifier (x)
    └── BinaryExpression (+)
        ├── Literal (5)
        └── Literal (3)
```

Because of this, my first assumption was:

> "I need to convert this AST back into JavaScript."

This turned out to be **the wrong objective**, even though it sounds perfectly reasonable.

---

# Attempt 1 – Regenerating the Source Code

After reading about ASTs, I found that libraries like **Babel** are capable of generating JavaScript from an AST.

So I tried using Babel's code generator.

Unfortunately, it immediately failed with errors similar to:

```
Unknown node type: Literal
```

I then tried another library with the same result.

At this point I assumed that I was using the wrong tool.

In reality, something else was happening.

---

# Why Babel Failed

The challenge does **not** use Babel's AST format.

Although ASTs all represent source code, there is **no universal AST specification**.

Different parsers produce different node types.

For example:

### ESTree

```json
{
    "type": "Literal",
    "value": 10
}
```

### Babel

```json
{
    "type": "NumericLiteral",
    "value": 10
}
```

The provided AST follows an ESTree-like format while Babel expects Babel nodes.

Even more interesting, the challenge intentionally includes an invalid node at the end:

```json
{
    "type": "jaajajajajajajajajajajajaj"
}
```

Clearly, no parser understands that node.

This is a good indication that the author wanted to discourage blindly relying on automatic tooling.

---

# The Real Objective

After spending some time trying to reconstruct the original JavaScript, I realized something important.

The goal of reverse engineering is **not** to recover the original source code.

The goal is to recover the **behavior**.

The AST already contains every piece of information necessary to understand the algorithm.

Instead of trying to regenerate JavaScript, I started reading the tree directly.

---

# Reading the AST

One advantage of ASTs is that they are actually very systematic.

For example:

```
VariableDeclaration
```

immediately translates to

```javascript
let ...
```

A

```
CallExpression
```

means

```javascript
something(...)
```

An

```
ArrowFunctionExpression
```

means

```javascript
x => ...
```

After following the nodes, the first part of the AST can be reconstructed almost mechanically as

```javascript
(() => {

    let d = [
        1856,
        1824,
        1776,
        1728,
        1776,
        1728,
        1776
    ];

    d = d.map(c => String.fromCharCode(c >> 4));

    console.log(d);

})();
```

This immediately tells us that the author is simply right-shifting numbers before converting them into ASCII characters.

No AST generator was required.

---

# Finding the Interesting Part

The only function that looked meaningful was

```javascript
function gen_sensor()
```

This is most likely what the challenge description refers to.

Inside the function, the first variable is built in a strange way:

```javascript
let sens = [10] + [45] + [65] + [78] + [47];
```

At first this looks confusing.

However, JavaScript converts arrays into strings when using the `+` operator.

Therefore

```javascript
[10]
```

becomes

```javascript
"10"
```

and eventually

```javascript
sens = "1045657847"
```

Immediately afterwards we see

```javascript
sens >>= 4;
```

Bitwise operators force JavaScript to convert the string into an integer.

So the actual key becomes

```javascript
sens = 1045657847 >> 4;
```

which evaluates to

```text
65353615
```

This value is later used throughout the rest of the function.

---

# Recovering the Sensor

The remainder of the function performs exactly the following steps:

1. Create an array of integers.
2. XOR every integer with `sens`.
3. Convert the result into ASCII.
4. Join every character together.

In other words:

```
Encrypted Numbers
        │
        ▼
XOR with sens
        │
        ▼
ASCII Characters
        │
        ▼
Sensor String
```

Recognizing this pattern is much more important than reconstructing the original JavaScript.

---

# Solving It

Instead of rebuilding the entire program, a tiny Python script is enough.

```python
cipher = [
    65353704,65353663,65353663,65353707,65353680,
    65353701,65353663,65353709,65353680,65353706,
    65353710,65353724,65353718,65353680,65353707,
    65353706,65353696,65353709,65353705,65353722,
    65353724,65353708,65353710,65353723,65353702,
    65353696,65353697
]

sens = 1045657847 >> 4

result = "".join(chr(x ^ sens) for x in cipher)

print(result)
```

The important observation is that we never needed to regenerate JavaScript.

We only needed to understand the algorithm and reproduce it.

---

# Lessons Learned

This challenge taught me something that applies to almost every reverse engineering problem.

Initially, my workflow looked like this:

```
AST
    ↓
Find an AST generator
    ↓
Recover JavaScript
    ↓
Understand the code
```

The better workflow is

```
AST
    ↓
Understand the nodes
    ↓
Recover the algorithm
    ↓
Automate repetitive operations
    ↓
Extract the result
```

Reverse engineering is about **recovering semantics**, not **recovering syntax**.

The original source code is only one representation of the program.

An AST already contains all the information necessary to understand its behavior.

---

# Takeaways

* Learn to recognize common AST nodes instead of depending entirely on code generators.
* Do not assume every AST is compatible with Babel or another parser.
* Small helper scripts are usually more useful than building or finding a complete decompiler.
* Focus on understanding **what** the program does rather than recreating **how** it was originally written.
* In reverse engineering, the shortest path to the solution is often understanding the algorithm—not reconstructing the source.

---

# Final Thoughts

Looking back, my biggest mistake was chasing the "perfect" reconstruction of the original JavaScript.

Ironically, that wasn't necessary at all.

The AST already exposed the entire algorithm; I just had to read it.

This challenge was an excellent reminder that reverse engineering is fundamentally about **understanding behavior**. Once I shifted my mindset from *"How do I regenerate the code?"* to *"What is this program actually doing?"*, the solution became much more straightforward.

Sometimes the best decompiler is simply your understanding of the data structure in front of you.
