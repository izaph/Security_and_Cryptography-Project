# Custom Cryptography (ChaCha20, TEA, RSA)

A Command Line Interface (CLI) cryptographic application written in pure C. This tool implements two symmetric ciphers (**ChaCha20** and **TEA**) alongside an asymmetric cryptosystem (**RSA**). It tracks microsecond-accurate data processing metrics to evaluate execution throughput and performance efficiency under high workloads.

---

## 🛠️ Compilation & Environment Setup

This project compiles smoothly on Windows systems using the `gcc` compiler package via **MSYS2**.

To compile the application, launch your terminal tool, map your environment paths to your compiler toolchain binary folder, and trigger the compilation flags:

```cmd
1. Link your shell instance to your MSYS2 toolchain bin directory
SET PATH=C:\msys64\ucrt64\bin;%PATH%

2. Compile the source code into the required system executable
gcc project.c -o crypto
