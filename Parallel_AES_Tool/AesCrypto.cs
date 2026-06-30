// ============================================================================
//  AesCrypto.cs  -  Core engine of the "High-Speed Parallel File Encryption
//                   Tool using AES" (TPC6323 Parallel Computing project).
//
//  This single file contains everything that does the actual cryptography and
//  parallel processing. The Windows Forms UI (MainForm.cs) only calls into the
//  three public methods: Encrypt, Decrypt and Benchmark.
//
//  Why AES-256 in CTR (Counter) mode?
//  ----------------------------------
//  CTR mode turns a block cipher into a stream cipher. For every 16-byte block
//  it builds a "counter block" (nonce + block index), encrypts THAT counter to
//  produce a keystream, and XORs the keystream with the plaintext:
//
//        keystream(i) = AES_Encrypt(nonce || i)
//        cipher(i)    = plain(i) XOR keystream(i)
//
//  The key property for THIS project: block i depends only on its own index i,
//  never on block i-1. There is no chaining between blocks (unlike CBC/CFB).
//  That independence is exactly what lets us process blocks in parallel and
//  still get the same result as a sequential run. Do NOT switch to a chaining
//  mode - it would break the whole thesis of the assignment.
//
//  Note: encryption and decryption are the SAME operation in CTR mode (XOR is
//  its own inverse), which is why both Encrypt and Decrypt call the same
//  TransformParallelFor / Worker.Process code path.
//
//  Security layers added on top of raw AES-CTR:
//    * PBKDF2 (Rfc2898DeriveBytes) turns the user password into strong keys.
//    * A random per-file salt    -> same password never derives the same key.
//    * A random per-file nonce   -> same key/plaintext never reuses keystream.
//    * HMAC-SHA256 over the data -> detects tampering or a wrong password
//                                   (this is the "encrypt-then-MAC" pattern).
// ============================================================================

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Parallel_AES_Tool
{
    // Result for ONE parallel strategy in the benchmark (e.g. "Parallel.For").
    // Plain public fields keep it a simple data carrier passed back to the UI.
    internal sealed class ParallelBenchmarkResult
    {
        public string Name;            // human-readable algorithm name shown in the grid
        public string Strategy;        // short description of how the work is split
        public long Milliseconds;      // wall-clock time this strategy took
        public double ThroughputMBs;   // processing speed in megabytes per second
        public double Speedup;         // sequential time / this time  (higher = faster)
        public bool Verified;          // true if output byte-for-byte matches the sequential baseline
    }

    // Aggregated benchmark output for one input file: the sequential baseline
    // plus one ParallelBenchmarkResult per parallel strategy that was tested.
    internal sealed class BenchmarkResult
    {
        public long FileBytes;                       // size of the benchmarked file
        public long SequentialMilliseconds;          // baseline time (single worker, no parallelism)
        public double SequentialThroughputMBs;       // baseline throughput
        public List<ParallelBenchmarkResult> ParallelAlgorithms = new List<ParallelBenchmarkResult>();
    }

    // Static helper class = the whole crypto engine. "static" because it holds
    // no state of its own; every call is self-contained.
    internal static class AesCtrFile
    {
        // ---- File-format constants (the layout of a .tpcaes file) -----------
        // A magic marker written at the start of every encrypted file so we can
        // reject files that were not produced by this tool. ("TPCAES01" = 8 bytes)
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("TPCAES01");
        private const int SaltLength = 16;     // PBKDF2 salt, random per file
        private const int NonceLength = 8;     // CTR nonce, random per file
        private const int HeaderLength = 44;   // total header size (see BuildHeader for the byte map)
        private const int HmacLength = 32;     // HMAC-SHA256 produces 32 bytes
        private const int Iterations = 100000; // PBKDF2 work factor (slows brute-force guessing)

        // On-disk layout of an encrypted file:
        //   [ 44-byte header ][ ciphertext (same length as plaintext) ][ 32-byte HMAC tag ]

        // ------------------------------------------------------------------ //
        //  PUBLIC API  (the three operations the UI exposes)                  //
        // ------------------------------------------------------------------ //

        // Encrypt a file: derive keys, encrypt in parallel, then append an
        // authentication tag so tampering can be detected on decrypt.
        public static void Encrypt(string inputPath, string outputPath, string password, int parallelism)
        {
            byte[] plain = File.ReadAllBytes(inputPath);          // load whole file into memory
            byte[] salt = RandomBytes(SaltLength);                // fresh random salt for this file
            byte[] nonce = RandomBytes(NonceLength);              // fresh random nonce for CTR

            KeyMaterial keys = DeriveKeys(password, salt);        // password + salt -> AES key + HMAC key

            byte[] cipher = TransformParallelFor(plain, keys.AesKey, nonce, parallelism); // the parallel work
            byte[] header = BuildHeader(salt, nonce, plain.LongLength);

            // Encrypt-then-MAC: the tag covers BOTH the header and the ciphertext,
            // so any change to either is detected before we ever decrypt.
            byte[] tag = ComputeTag(keys.HmacKey, header, cipher);

            using (FileStream stream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                stream.Write(header, 0, header.Length);
                stream.Write(cipher, 0, cipher.Length);
                stream.Write(tag, 0, tag.Length);
            }
        }

        // Decrypt a file: re-derive keys from the stored salt, VERIFY the tag
        // first, and only then undo the CTR transform.
        public static void Decrypt(string inputPath, string outputPath, string password, int parallelism)
        {
            byte[] package = File.ReadAllBytes(inputPath);
            // A valid file must be at least header + tag in size.
            if (package.Length < HeaderLength + HmacLength) throw new InvalidDataException("Encrypted file is too short.");
            byte[] header = Slice(package, 0, HeaderLength);
            Header parsed = ParseHeader(header);                                   // read magic, salt, nonce, length
            int cipherLength = package.Length - HeaderLength - HmacLength;         // everything between header and tag
            byte[] cipher = Slice(package, HeaderLength, cipherLength);
            byte[] expectedTag = Slice(package, HeaderLength + cipherLength, HmacLength);
            KeyMaterial keys = DeriveKeys(password, parsed.Salt);                  // same salt -> same keys as encryption
            // Recompute the tag and compare in constant time. If the password is
            // wrong OR the file was tampered with, the tags differ and we abort
            // BEFORE decrypting (fail-closed, never emit untrusted plaintext).
            if (!FixedTimeEquals(expectedTag, ComputeTag(keys.HmacKey, header, cipher))) throw new CryptographicException("Authentication failed. Password or file contents are invalid.");
            byte[] plain = TransformParallelFor(cipher, keys.AesKey, parsed.Nonce, parallelism); // XOR is its own inverse
            // Sanity check: recovered size must match the length stored at encrypt time.
            if (plain.LongLength != parsed.OriginalLength) throw new InvalidDataException("Decrypted length does not match the header.");
            File.WriteAllBytes(outputPath, plain);
        }

        // Benchmark mode: encrypt the same data with a sequential baseline and
        // every parallel strategy, timing each and verifying they all produce
        // identical output. These numbers feed Section 4 (Results) of the report.
        // NOTE: salt/nonce are all-zero here ON PURPOSE - benchmarking only needs
        // consistent, comparable timings, not a securely stored file.
        public static BenchmarkResult Benchmark(string inputPath, string password, int parallelism)
        {
            byte[] data = File.ReadAllBytes(inputPath);
            byte[] salt = new byte[SaltLength];     // zero salt (benchmark only)
            byte[] nonce = new byte[NonceLength];   // zero nonce (benchmark only)
            KeyMaterial keys = DeriveKeys(password, salt);
            BenchmarkResult result = new BenchmarkResult();
            result.FileBytes = data.LongLength;

            // 1) Run the single-threaded baseline first and KEEP its output so
            //    every parallel strategy can be checked against it for correctness.
            byte[] sequentialOutput = null;
            result.SequentialMilliseconds = Measure(delegate { sequentialOutput = TransformSequential(data, keys.AesKey, nonce); });
            result.SequentialThroughputMBs = Throughput(result.FileBytes, result.SequentialMilliseconds);

            // 2) Run each parallel strategy. AddBenchmark times it, verifies it
            //    against the baseline, and records throughput + speedup.
            AddBenchmark(result, "Parallel.For block loop", "TPL block-level data parallelism", delegate { return TransformParallelFor(data, keys.AesKey, nonce, parallelism); }, sequentialOutput);
            AddBenchmark(result, "Static chunk tasks", "Fixed contiguous block ranges", delegate { return TransformStaticChunkTasks(data, keys.AesKey, nonce, parallelism); }, sequentialOutput);
            AddBenchmark(result, "Dynamic chunk tasks", "Dynamic work allocation with Interlocked", delegate { return TransformDynamicChunkTasks(data, keys.AesKey, nonce, parallelism); }, sequentialOutput);
            AddBenchmark(result, "Parallel.ForEach partitions", "Range partitioner scheduling", delegate { return TransformPartitionedForEach(data, keys.AesKey, nonce, parallelism); }, sequentialOutput);
            return result;
        }

        // Times one strategy, confirms its output matches the sequential result,
        // and appends a row to the benchmark result. Throws if the output differs
        // (a parallel bug must never silently produce wrong ciphertext).
        private static void AddBenchmark(BenchmarkResult result, string name, string strategy, Func<byte[]> transform, byte[] expectedOutput)
        {
            byte[] output = null;
            long elapsed = Measure(() => output = transform());
            bool verified = ByteArrayEquals(expectedOutput, output);

            if (!verified)
                throw new CryptographicException(name + " produced output different from sequential AES-CTR.");

            result.ParallelAlgorithms.Add(new ParallelBenchmarkResult
            {
                Name = name,
                Strategy = strategy,
                Milliseconds = elapsed,
                ThroughputMBs = Throughput(result.FileBytes, elapsed),
                Speedup = (double)result.SequentialMilliseconds / elapsed, // baseline / parallel
                Verified = verified
            });
        }

        // ------------------------------------------------------------------ //
        //  PARALLEL STRATEGIES                                                //
        //  Four different ways to split the same per-block work across CPU    //
        //  cores. They all call the identical Worker.Process per block, so    //
        //  the ONLY thing being compared is the work-distribution scheme.     //
        //  Each thread gets its OWN Worker (its own AES object) because a      //
        //  single ICryptoTransform is NOT safe to share across threads.       //
        // ------------------------------------------------------------------ //

        // STRATEGY 1 - Parallel.For (the project's primary, recommended approach).
        // The TPL splits the block range [0, blocks) across threads for us. The
        // thread-local overload gives each thread one reusable Worker, so we
        // create at most "parallelism" AES objects instead of one per block.
        private static byte[] TransformParallelFor(byte[] input, byte[] key, byte[] nonce, int parallelism)
        {
            byte[] output = new byte[input.Length];
            int blocks = BlockCount(input);
            Parallel.For<Worker>(
                0, blocks,
                CreateOptions(parallelism),                 // MaxDegreeOfParallelism = thread count
                () => new Worker(key, nonce),               // thread-local init: one Worker per thread
                (block, state, worker) => { worker.Process(input, output, block); return worker; }, // body
                worker => worker.Dispose());                // thread-local cleanup
            return output;
        }

        // STRATEGY 2 - Static chunking. Split the blocks into N equal contiguous
        // ranges up front (one per worker) and start a Task for each. Simple and
        // low-overhead, but if some ranges finish early their cores sit idle
        // (poor load balancing when work per block is uneven).
        private static byte[] TransformStaticChunkTasks(byte[] input, byte[] key, byte[] nonce, int parallelism)
        {
            byte[] output = new byte[input.Length];
            int blocks = BlockCount(input);
            int workers = WorkerCount(blocks, parallelism);
            int chunk = (blocks + workers - 1) / workers;   // ceil(blocks / workers) = blocks per worker
            Task[] tasks = new Task[workers];
            for (int taskIndex = 0; taskIndex < workers; taskIndex++)
            {
                int start = taskIndex * chunk;
                int end = Math.Min(blocks, start + chunk);  // clamp last range to the real end
                tasks[taskIndex] = Task.Factory.StartNew(delegate
                {
                    using (Worker worker = new Worker(key, nonce))
                    {
                        for (int block = start; block < end; block++) worker.Process(input, output, block);
                    }
                });
            }
            Task.WaitAll(tasks);
            return output;
        }

        // STRATEGY 3 - Dynamic chunking (work-stealing style). Instead of fixed
        // ranges, all workers pull small chunks from a shared counter until the
        // file is exhausted. Interlocked.Add hands out the next chunk atomically
        // (no locks). This balances load well when blocks take uneven time, at
        // the cost of more synchronization on the shared counter.
        private static byte[] TransformDynamicChunkTasks(byte[] input, byte[] key, byte[] nonce, int parallelism)
        {
            byte[] output = new byte[input.Length];
            int blocks = BlockCount(input);
            int workers = WorkerCount(blocks, parallelism);
            int chunk = Math.Max(1, blocks / Math.Max(1, workers * 8)); // many small chunks -> finer balancing
            int nextBlock = 0;                                          // SHARED cursor across all workers
            Task[] tasks = new Task[workers];
            for (int taskIndex = 0; taskIndex < workers; taskIndex++)
            {
                tasks[taskIndex] = Task.Factory.StartNew(delegate
                {
                    using (Worker worker = new Worker(key, nonce))
                    {
                        while (true)
                        {
                            // Atomically reserve the next "chunk" blocks. Add returns
                            // the value AFTER adding, so subtract chunk to get our start.
                            int start = Interlocked.Add(ref nextBlock, chunk) - chunk;
                            if (start >= blocks) break;                 // nothing left -> this worker is done
                            int end = Math.Min(blocks, start + chunk);
                            for (int block = start; block < end; block++) worker.Process(input, output, block);
                        }
                    }
                });
            }
            Task.WaitAll(tasks);
            return output;
        }

        // STRATEGY 4 - Parallel.ForEach over a range Partitioner. The Partitioner
        // pre-slices [0, blocks) into tuples (start, end) and the TPL schedules
        // them. Conceptually between strategy 1 and 3: chunked like static, but
        // the runtime balances the chunks across threads for us.
        private static byte[] TransformPartitionedForEach(byte[] input, byte[] key, byte[] nonce, int parallelism)
        {
            byte[] output = new byte[input.Length];
            int blocks = BlockCount(input);
            int rangeSize = Math.Max(1, blocks / Math.Max(1, parallelism * 8));        // target chunk size
            OrderablePartitioner<Tuple<int, int>> ranges = Partitioner.Create(0, blocks, rangeSize);
            Parallel.ForEach<Tuple<int, int>, Worker>(ranges, CreateOptions(parallelism), delegate { return new Worker(key, nonce); }, delegate(Tuple<int, int> range, ParallelLoopState state, Worker worker)
            {
                // range.Item1 = inclusive start, range.Item2 = exclusive end.
                for (int block = range.Item1; block < range.Item2; block++) worker.Process(input, output, block);
                return worker;
            }, delegate(Worker worker) { worker.Dispose(); });
            return output;
        }

        // The sequential baseline: one worker, processes every block in order.
        // This is the reference that all parallel strategies are timed against
        // (speedup) and verified against (correctness).
        private static byte[] TransformSequential(byte[] input, byte[] key, byte[] nonce)
        {
            byte[] output = new byte[input.Length];
            int blocks = BlockCount(input);
            using (Worker worker = new Worker(key, nonce))
            {
                for (int i = 0; i < blocks; i++)
                {
                    worker.Process(input, output, i);
                }
            }
            return output;
        }

        // ------------------------------------------------------------------ //
        //  SMALL HELPERS                                                      //
        // ------------------------------------------------------------------ //

        // Caps how many threads the TPL may use. This is the "configurable
        // parallelism degree" the report treats as an experimental variable.
        private static ParallelOptions CreateOptions(int parallelism)
        {
            return new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, parallelism) };
        }

        private static int BlockCount(byte[] input)
        {
            // Round the byte length up to whole 16-byte AES blocks.
            return (input.Length + 15) / 16;
        }

        // Don't spin up more workers than there are blocks to process.
        private static int WorkerCount(int blocks, int parallelism)
        {
            int degree = Math.Max(1, parallelism);
            int usable = Math.Max(1, blocks);
            return Math.Min(degree, usable);
        }

        // Convert (bytes, milliseconds) into MB/s for the results table.
        private static double Throughput(long bytes, long milliseconds)
        {
            if (milliseconds <= 0) return 0.0;
            double megabytes = bytes / (1024.0 * 1024.0);
            double seconds = milliseconds / 1000.0;
            return megabytes / seconds;
        }

        // ------------------------------------------------------------------ //
        //  FILE HEADER  (44 bytes, fixed layout)                              //
        //    offset  0..7   : magic "TPCAES01"                                //
        //    offset  8..23  : 16-byte salt                                    //
        //    offset 24..31  : 8-byte nonce                                    //
        //    offset 32..39  : original plaintext length (Int64, big-endian)   //
        //    offset 40..43  : PBKDF2 iteration count (Int32, big-endian)      //
        // ------------------------------------------------------------------ //

        private static byte[] BuildHeader(byte[] salt, byte[] nonce, long length)
        {
            byte[] header = new byte[HeaderLength];
            Buffer.BlockCopy(Magic, 0, header, 0, Magic.Length);   // bytes 0..7
            Buffer.BlockCopy(salt, 0, header, 8, SaltLength);      // bytes 8..23
            Buffer.BlockCopy(nonce, 0, header, 24, NonceLength);   // bytes 24..31
            WriteInt64(header, 32, length);                        // bytes 32..39
            WriteInt32(header, 40, Iterations);                    // bytes 40..43
            return header;
        }

        // Reverse of BuildHeader. Validates the magic and iteration count, then
        // returns the salt/nonce/length we need to reconstruct the keys.
        private static Header ParseHeader(byte[] header)
        {
            for (int i = 0; i < Magic.Length; i++) if (header[i] != Magic[i]) throw new InvalidDataException("Invalid encrypted file format.");
            if (ReadInt32(header, 40) != Iterations) throw new InvalidDataException("Unsupported encrypted file format.");
            return new Header { Salt = Slice(header, 8, SaltLength), Nonce = Slice(header, 24, NonceLength), OriginalLength = ReadInt64(header, 32) };
        }

        // ------------------------------------------------------------------ //
        //  KEY DERIVATION & AUTHENTICATION                                    //
        // ------------------------------------------------------------------ //

        // PBKDF2: stretch the password into 64 bytes of key material using the
        // per-file salt and a high iteration count (slows down brute-force
        // attacks). We split the 64 bytes into two independent 32-byte keys so
        // the same bytes are never reused for both encryption and authentication.
        private static KeyMaterial DeriveKeys(string password, byte[] salt)
        {
            using (Rfc2898DeriveBytes derive = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                byte[] material = derive.GetBytes(64);
                return new KeyMaterial
                {
                    AesKey = Slice(material, 0, 32),   // first 32 bytes -> AES-256 key
                    HmacKey = Slice(material, 32, 32)  // last 32 bytes  -> HMAC key
                };
            }
        }

        // Compute HMAC-SHA256 over header THEN ciphertext (encrypt-then-MAC).
        // TransformBlock/TransformFinalBlock feed both buffers into one HMAC pass
        // without allocating a combined array.
        private static byte[] ComputeTag(byte[] key, byte[] header, byte[] cipher)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                hmac.TransformBlock(header, 0, header.Length, null, 0);
                hmac.TransformFinalBlock(cipher, 0, cipher.Length);
                return hmac.Hash;
            }
        }

        // ------------------------------------------------------------------ //
        //  TIMING, RANDOMNESS & BYTE UTILITIES                                //
        // ------------------------------------------------------------------ //

        // Time one action with a Stopwatch. Forces a full GC first so leftover
        // garbage from a previous run can't pause us mid-measurement and skew
        // the timing. Returns at least 1 ms to avoid divide-by-zero in speedup.
        private static long Measure(Action action)
        {
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            Stopwatch timer = Stopwatch.StartNew(); action(); timer.Stop();
            return Math.Max(1, timer.ElapsedMilliseconds);
        }

        // Cryptographically secure random bytes (used for salt and nonce).
        // RandomNumberGenerator is unpredictable, unlike System.Random.
        private static byte[] RandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        // Copy a sub-range of a byte array into a new array.
        private static byte[] Slice(byte[] source, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, offset, result, 0, count);
            return result;
        }

        // Constant-time comparison: always scans every byte so an attacker cannot
        // learn how many leading bytes matched from the response timing. Used for
        // the security-critical HMAC tag check.
        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) // scan every byte (no early exit)
            {
                diff |= a[i] ^ b[i];           // any differing byte sets a bit in diff
            }
            return diff == 0;
        }

        // Same idea as FixedTimeEquals but for the benchmark's correctness check,
        // where timing-safety doesn't matter; it just compares two outputs.
        private static bool ByteArrayEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }

        // Big-endian (most significant byte first) integer serialization,
        // so the header layout is identical on any machine regardless of the
        // CPU's native byte order.
        private static void WriteInt64(byte[] buffer, int offset, long value)
        {
            for (int i = 7; i >= 0; i--)
            {
                buffer[offset + (7 - i)] = (byte)((value >> (i * 8)) & 255);
            }
        }

        private static long ReadInt64(byte[] buffer, int offset)
        {
            long value = 0;
            for (int i = 0; i < 8; i++)
            {
                value = (value << 8) | buffer[offset + i]; // shift in one byte at a time
            }
            return value;
        }

        private static void WriteInt32(byte[] buffer, int offset, int value)
        {
            for (int i = 3; i >= 0; i--)
            {
                buffer[offset + (3 - i)] = (byte)((value >> (i * 8)) & 255);
            }
        }

        private static int ReadInt32(byte[] buffer, int offset)
        {
            int value = 0;
            for (int i = 0; i < 4; i++)
            {
                value = (value << 8) | buffer[offset + i];
            }
            return value;
        }

        // Small private data holders. Header carries parsed file metadata;
        // KeyMaterial carries the two derived keys.
        private sealed class Header { public byte[] Salt; public byte[] Nonce; public long OriginalLength; }
        private sealed class KeyMaterial { public byte[] AesKey; public byte[] HmacKey; }

        // ------------------------------------------------------------------ //
        //  Worker - the per-thread AES-CTR engine                            //
        //  One Worker = one AES object that can encrypt any block by index.  //
        //  Each thread owns its own Worker because ICryptoTransform is NOT   //
        //  thread-safe; sharing one would corrupt the keystream.             //
        // ------------------------------------------------------------------ //
        private sealed class Worker : IDisposable
        {
            private readonly AesManaged aes;            // the AES algorithm instance
            private readonly ICryptoTransform encryptor;// reusable block encryptor
            private readonly byte[] nonce;              // per-file nonce (first half of every counter)
            private readonly byte[] counter = new byte[16]; // scratch: the 16-byte counter block
            private readonly byte[] stream = new byte[16];  // scratch: the 16-byte keystream output

            public Worker(byte[] key, byte[] nonce)
            {
                this.nonce = nonce;
                // ECB with no padding is used as a raw 16-byte block primitive:
                // we feed it ONE counter block and get ONE keystream block back.
                // (This is a textbook way to build CTR mode from a block cipher;
                // we are NOT using ECB to encrypt the file directly.)
                aes = new AesManaged { Mode = CipherMode.ECB, Padding = PaddingMode.None, KeySize = 256, Key = key };
                encryptor = aes.CreateEncryptor();
            }

            // Encrypt/decrypt a single 16-byte block at position "block".
            // Because CTR is symmetric, this same method handles both directions.
            public void Process(byte[] input, byte[] output, int block)
            {
                // Build the counter block = nonce (8 bytes) || block index (8 bytes).
                Buffer.BlockCopy(nonce, 0, counter, 0, nonce.Length);

                // append big-endian block index to form the counter block
                for (int i = 7; i >= 0; i--)
                {
                    counter[8 + (7 - i)] = (byte)(((ulong)block >> (i * 8)) & 255);
                }

                // keystream block = AES_Encrypt(counter). This is the only AES call.
                encryptor.TransformBlock(counter, 0, 16, stream, 0);

                int offset = block * 16;                              // where this block sits in the file
                int remaining = Math.Min(16, input.Length - offset);  // last block may be < 16 bytes

                // XOR plaintext with keystream -> ciphertext (or vice versa).
                for (int i = 0; i < remaining; i++)
                {
                    output[offset + i] = (byte)(input[offset + i] ^ stream[i]);
                }
            }

            // Release the unmanaged crypto handles and wipe the AES key from memory.
            public void Dispose() { encryptor.Dispose(); aes.Clear(); }
        }
    }
}
