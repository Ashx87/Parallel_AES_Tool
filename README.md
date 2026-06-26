# Parallel AES Tool

High-speed parallel file encryption tool using **AES-256 in CTR mode**, built as a C# Windows Forms application. Developed for **TPC6323 Parallel Computing** at Multimedia University (MMU).

The tool encrypts and decrypts files of any type, and includes a benchmark mode that compares sequential AES-CTR against several CPU-parallel strategies built on the .NET Task Parallel Library (TPL).

## Features

- **AES-256 in CTR mode** — each 16-byte counter block is independent, which is what makes block-level parallelism correct.
- **Configurable parallelism** — choose the number of CPU threads (1–64) used by the parallel encryptors.
- **Password-based keys** — PBKDF2 (HMAC-SHA256, 100,000 iterations) with a random per-file salt.
- **Authenticated encryption** — HMAC-SHA256 over the header and ciphertext (encrypt-then-MAC) detects a wrong password or a tampered file.
- **Benchmark mode** — measures execution time, throughput (MB/s) and speedup for the sequential baseline and four parallel strategies, each verified byte-for-byte against the sequential result:
  - `Parallel.For` block loop
  - Static chunk tasks
  - Dynamic chunk tasks (work-stealing with `Interlocked`)
  - `Parallel.ForEach` with a range partitioner

## Requirements

- Windows
- .NET Framework 4.8
- Visual Studio 2022 or newer (to open `Parallel_AES_Tool.slnx`)

## Build & run

```
# Open the solution in Visual Studio and press F5,
# or build from the command line with MSBuild:
msbuild Parallel_AES_Tool/Parallel_AES_Tool.csproj /t:Build /p:Configuration=Release
```

The executable is produced under `Parallel_AES_Tool/bin/Release/`.

## Usage

1. **Input file** — browse to any file to encrypt or decrypt.
2. **Output file** — a suggested path is filled in automatically (`.tpcaes` for encryption, `-restored` for decryption).
3. **Password** — used to derive the encryption and authentication keys.
4. **CPU threads** — degree of parallelism.
5. Click **Encrypt**, **Decrypt**, or **Run benchmark**.

## Encrypted file format

```
magic ("TPCAES01", 8 bytes)
salt (16 bytes)
nonce (8 bytes)
original length (int64, big-endian)
iterations (int32, big-endian)
ciphertext (AES-256-CTR)
HMAC-SHA256 tag (32 bytes)
```

## Project structure

```
Parallel_AES_Tool/
  Parallel_AES_Tool.slnx        Solution
  Parallel_AES_Tool/
    Program.cs                  Application entry point
    MainForm.cs                 Windows Forms UI (encrypt / decrypt / benchmark)
    AesCrypto.cs                AES-CTR core, key derivation, HMAC, parallel strategies
```

## Notes

This is an academic prototype. It uses the managed `AesManaged` implementation (no AES-NI hardware acceleration) deliberately, so that encryption stays CPU-bound and the benefit of parallelism is clearly observable in the benchmark.
