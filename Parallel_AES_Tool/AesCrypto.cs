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
    internal sealed class ParallelBenchmarkResult
    {
        public string Name;
        public string Strategy;
        public long Milliseconds;
        public double ThroughputMBs;
        public double Speedup;
        public bool Verified;
    }

    internal sealed class BenchmarkResult
    {
        public long FileBytes;
        public long SequentialMilliseconds;
        public double SequentialThroughputMBs;
        public List<ParallelBenchmarkResult> ParallelAlgorithms = new List<ParallelBenchmarkResult>();
    }

    internal static class AesCtrFile
    {
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("TPCAES01");
        private const int SaltLength = 16;
        private const int NonceLength = 8;
        private const int HeaderLength = 44;
        private const int HmacLength = 32;
        private const int Iterations = 100000;

        public static void Encrypt(string inputPath, string outputPath, string password, int parallelism)
        {
            byte[] plain = File.ReadAllBytes(inputPath);
            byte[] salt = RandomBytes(SaltLength);
            byte[] nonce = RandomBytes(NonceLength);
            KeyMaterial keys = DeriveKeys(password, salt);
            byte[] cipher = TransformParallelFor(plain, keys.AesKey, nonce, parallelism);
            byte[] header = BuildHeader(salt, nonce, plain.LongLength);
            byte[] tag = ComputeTag(keys.HmacKey, header, cipher);
            using (FileStream stream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                stream.Write(header, 0, header.Length);
                stream.Write(cipher, 0, cipher.Length);
                stream.Write(tag, 0, tag.Length);
            }
        }

        public static void Decrypt(string inputPath, string outputPath, string password, int parallelism)
        {
            byte[] package = File.ReadAllBytes(inputPath);
            if (package.Length < HeaderLength + HmacLength) throw new InvalidDataException("Encrypted file is too short.");
            byte[] header = Slice(package, 0, HeaderLength);
            Header parsed = ParseHeader(header);
            int cipherLength = package.Length - HeaderLength - HmacLength;
            byte[] cipher = Slice(package, HeaderLength, cipherLength);
            byte[] expectedTag = Slice(package, HeaderLength + cipherLength, HmacLength);
            KeyMaterial keys = DeriveKeys(password, parsed.Salt);
            if (!FixedTimeEquals(expectedTag, ComputeTag(keys.HmacKey, header, cipher))) throw new CryptographicException("Authentication failed. Password or file contents are invalid.");
            byte[] plain = TransformParallelFor(cipher, keys.AesKey, parsed.Nonce, parallelism);
            if (plain.LongLength != parsed.OriginalLength) throw new InvalidDataException("Decrypted length does not match the header.");
            File.WriteAllBytes(outputPath, plain);
        }

        public static BenchmarkResult Benchmark(string inputPath, string password, int parallelism)
        {
            byte[] data = File.ReadAllBytes(inputPath);
            byte[] salt = new byte[SaltLength];
            byte[] nonce = new byte[NonceLength];
            KeyMaterial keys = DeriveKeys(password, salt);
            BenchmarkResult result = new BenchmarkResult();
            result.FileBytes = data.LongLength;
            byte[] sequentialOutput = null;
            result.SequentialMilliseconds = Measure(delegate { sequentialOutput = TransformSequential(data, keys.AesKey, nonce); });
            result.SequentialThroughputMBs = Throughput(result.FileBytes, result.SequentialMilliseconds);

            AddBenchmark(result, "Parallel.For block loop", "TPL block-level data parallelism", delegate { return TransformParallelFor(data, keys.AesKey, nonce, parallelism); }, sequentialOutput);
            AddBenchmark(result, "Static chunk tasks", "Fixed contiguous block ranges", delegate { return TransformStaticChunkTasks(data, keys.AesKey, nonce, parallelism); }, sequentialOutput);
            AddBenchmark(result, "Dynamic chunk tasks", "Dynamic work allocation with Interlocked", delegate { return TransformDynamicChunkTasks(data, keys.AesKey, nonce, parallelism); }, sequentialOutput);
            AddBenchmark(result, "Parallel.ForEach partitions", "Range partitioner scheduling", delegate { return TransformPartitionedForEach(data, keys.AesKey, nonce, parallelism); }, sequentialOutput);
            return result;
        }

        private static void AddBenchmark(BenchmarkResult result, string name, string strategy, Func<byte[]> transform, byte[] expectedOutput)
        {
            byte[] output = null;
            long elapsed = Measure(delegate { output = transform(); });
            bool verified = ByteArrayEquals(expectedOutput, output);
            if (!verified) throw new CryptographicException(name + " produced output different from sequential AES-CTR.");
            result.ParallelAlgorithms.Add(new ParallelBenchmarkResult
            {
                Name = name,
                Strategy = strategy,
                Milliseconds = elapsed,
                ThroughputMBs = Throughput(result.FileBytes, elapsed),
                Speedup = (double)result.SequentialMilliseconds / elapsed,
                Verified = verified
            });
        }

        private static byte[] TransformParallelFor(byte[] input, byte[] key, byte[] nonce, int parallelism)
        {
            byte[] output = new byte[input.Length];
            int blocks = BlockCount(input);
            Parallel.For<Worker>(0, blocks, CreateOptions(parallelism), delegate { return new Worker(key, nonce); }, delegate(int block, ParallelLoopState state, Worker worker) { worker.Process(input, output, block); return worker; }, delegate(Worker worker) { worker.Dispose(); });
            return output;
        }

        private static byte[] TransformStaticChunkTasks(byte[] input, byte[] key, byte[] nonce, int parallelism)
        {
            byte[] output = new byte[input.Length];
            int blocks = BlockCount(input);
            int workers = WorkerCount(blocks, parallelism);
            int chunk = (blocks + workers - 1) / workers;
            Task[] tasks = new Task[workers];
            for (int taskIndex = 0; taskIndex < workers; taskIndex++)
            {
                int start = taskIndex * chunk;
                int end = Math.Min(blocks, start + chunk);
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

        private static byte[] TransformDynamicChunkTasks(byte[] input, byte[] key, byte[] nonce, int parallelism)
        {
            byte[] output = new byte[input.Length];
            int blocks = BlockCount(input);
            int workers = WorkerCount(blocks, parallelism);
            int chunk = Math.Max(1, blocks / Math.Max(1, workers * 8));
            int nextBlock = 0;
            Task[] tasks = new Task[workers];
            for (int taskIndex = 0; taskIndex < workers; taskIndex++)
            {
                tasks[taskIndex] = Task.Factory.StartNew(delegate
                {
                    using (Worker worker = new Worker(key, nonce))
                    {
                        while (true)
                        {
                            int start = Interlocked.Add(ref nextBlock, chunk) - chunk;
                            if (start >= blocks) break;
                            int end = Math.Min(blocks, start + chunk);
                            for (int block = start; block < end; block++) worker.Process(input, output, block);
                        }
                    }
                });
            }
            Task.WaitAll(tasks);
            return output;
        }

        private static byte[] TransformPartitionedForEach(byte[] input, byte[] key, byte[] nonce, int parallelism)
        {
            byte[] output = new byte[input.Length];
            int blocks = BlockCount(input);
            int rangeSize = Math.Max(1, blocks / Math.Max(1, parallelism * 8));
            OrderablePartitioner<Tuple<int, int>> ranges = Partitioner.Create(0, blocks, rangeSize);
            Parallel.ForEach<Tuple<int, int>, Worker>(ranges, CreateOptions(parallelism), delegate { return new Worker(key, nonce); }, delegate(Tuple<int, int> range, ParallelLoopState state, Worker worker)
            {
                for (int block = range.Item1; block < range.Item2; block++) worker.Process(input, output, block);
                return worker;
            }, delegate(Worker worker) { worker.Dispose(); });
            return output;
        }

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

        private static ParallelOptions CreateOptions(int parallelism)
        {
            return new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, parallelism) };
        }

        private static int BlockCount(byte[] input)
        {
            // Round the byte length up to whole 16-byte AES blocks.
            return (input.Length + 15) / 16;
        }

        private static int WorkerCount(int blocks, int parallelism)
        {
            int degree = Math.Max(1, parallelism);
            int usable = Math.Max(1, blocks);
            return Math.Min(degree, usable);
        }

        private static double Throughput(long bytes, long milliseconds)
        {
            if (milliseconds <= 0) return 0.0;
            double megabytes = bytes / (1024.0 * 1024.0);
            double seconds = milliseconds / 1000.0;
            return megabytes / seconds;
        }

        private static byte[] BuildHeader(byte[] salt, byte[] nonce, long length)
        {
            byte[] header = new byte[HeaderLength];
            Buffer.BlockCopy(Magic, 0, header, 0, Magic.Length);
            Buffer.BlockCopy(salt, 0, header, 8, SaltLength);
            Buffer.BlockCopy(nonce, 0, header, 24, NonceLength);
            WriteInt64(header, 32, length);
            WriteInt32(header, 40, Iterations);
            return header;
        }

        private static Header ParseHeader(byte[] header)
        {
            for (int i = 0; i < Magic.Length; i++) if (header[i] != Magic[i]) throw new InvalidDataException("Invalid encrypted file format.");
            if (ReadInt32(header, 40) != Iterations) throw new InvalidDataException("Unsupported encrypted file format.");
            return new Header { Salt = Slice(header, 8, SaltLength), Nonce = Slice(header, 24, NonceLength), OriginalLength = ReadInt64(header, 32) };
        }

        private static KeyMaterial DeriveKeys(string password, byte[] salt)
        {
            using (Rfc2898DeriveBytes derive = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                byte[] material = derive.GetBytes(64);
                return new KeyMaterial { AesKey = Slice(material, 0, 32), HmacKey = Slice(material, 32, 32) };
            }
        }

        private static byte[] ComputeTag(byte[] key, byte[] header, byte[] cipher)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                hmac.TransformBlock(header, 0, header.Length, null, 0);
                hmac.TransformFinalBlock(cipher, 0, cipher.Length);
                return hmac.Hash;
            }
        }

        private static long Measure(Action action)
        {
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            Stopwatch timer = Stopwatch.StartNew(); action(); timer.Stop();
            return Math.Max(1, timer.ElapsedMilliseconds);
        }

        private static byte[] RandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        private static byte[] Slice(byte[] source, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, offset, result, 0, count);
            return result;
        }

        // Constant-time comparison: always scans every byte so an attacker cannot
        // learn how many leading bytes matched from the response timing.
        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }

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
        // so the header layout is identical on any machine.
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
                value = (value << 8) | buffer[offset + i];
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

        private sealed class Header { public byte[] Salt; public byte[] Nonce; public long OriginalLength; }
        private sealed class KeyMaterial { public byte[] AesKey; public byte[] HmacKey; }

        private sealed class Worker : IDisposable
        {
            private readonly AesManaged aes;
            private readonly ICryptoTransform encryptor;
            private readonly byte[] nonce;
            private readonly byte[] counter = new byte[16];
            private readonly byte[] stream = new byte[16];
            public Worker(byte[] key, byte[] nonce)
            {
                this.nonce = nonce;
                aes = new AesManaged { Mode = CipherMode.ECB, Padding = PaddingMode.None, KeySize = 256, Key = key };
                encryptor = aes.CreateEncryptor();
            }
            public void Process(byte[] input, byte[] output, int block)
            {
                Buffer.BlockCopy(nonce, 0, counter, 0, nonce.Length);
                for (int i = 7; i >= 0; i--) counter[8 + (7 - i)] = (byte)(((ulong)block >> (i * 8)) & 255);
                encryptor.TransformBlock(counter, 0, 16, stream, 0);
                int offset = block * 16;
                int remaining = Math.Min(16, input.Length - offset);
                for (int i = 0; i < remaining; i++) output[offset + i] = (byte)(input[offset + i] ^ stream[i]);
            }
            public void Dispose() { encryptor.Dispose(); aes.Clear(); }
        }
    }
}
