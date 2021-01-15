using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;


namespace ParallelCryptography.Benchmarks
{
    [SimpleJob(RuntimeMoniker.NetCoreApp50), GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class HashAlgorithmBenchmarks
    {
        MD5 NativeMD5;
        SHA1 NativeSHA1;
        SHA256 NativeSHA256;
        SHA512 NativeSHA512;

        [GlobalSetup]
        public void Init()
        {
            NativeMD5 = MD5.Create();
            NativeSHA1 = SHA1.Create();
            NativeSHA256 = SHA256.Create();
            NativeSHA512 = SHA512.Create();
        }

        [BenchmarkCategory("MD5"), Benchmark(Baseline = true)]
        public byte[] Native_MD5_SingleHash_EmptyInput()
        {
            return NativeMD5.ComputeHash(Array.Empty<byte>());
        }

        [BenchmarkCategory("MD5"), Benchmark]
        public byte[] MD5_SingleHash_EmptyInput()
        {
            return HashFunctions.MD5(null);
        }

        [BenchmarkCategory("MD5"), Benchmark(OperationsPerInvoke = 4)]
        public byte[][] MD5_MultiHash_EmptyInput()
        {
            return HashFunctions.MD5Parallel(null, null, null, null);
        }

        [BenchmarkCategory("MD5"), Benchmark(OperationsPerInvoke = 8)]
        public byte[][] MD5_MultiHash_Avx2_EmptyInput()
        {
            return HashFunctions.MD5Parallel(null, null, null, null, null, null, null, null);
        }

        [BenchmarkCategory("SHA1"), Benchmark(Baseline = true)]
        public byte[] Native_SHA1_SingleHash_EmptyInput()
        {
            return NativeSHA1.ComputeHash(Array.Empty<byte>());
        }

        [BenchmarkCategory("SHA1"), Benchmark]
        public byte[] SHA1_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA1(null);
        }

        [BenchmarkCategory("SHA1"), Benchmark(OperationsPerInvoke = 4)]
        public byte[][] SHA1_MultiHash_EmptyInput()
        {
            return HashFunctions.SHA1Parallel(null, null, null, null);
        }

        [BenchmarkCategory("SHA256"), Benchmark(Baseline = true)]
        public byte[] Native_SHA256_SingleHash_EmptyInput()
        {
            return NativeSHA256.ComputeHash(Array.Empty<byte>());
        }

        [BenchmarkCategory("SHA256"), Benchmark]
        public byte[] SHA256_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA256(null);
        }

        [BenchmarkCategory("SHA256"), Benchmark(OperationsPerInvoke = 4)]
        public byte[][] SHA256_MultiHash_EmptyInput()
        {
            return HashFunctions.SHA256Parallel(null, null, null, null);
        }

        [BenchmarkCategory("SHA224"), Benchmark(Baseline = true)]
        public byte[] SHA224_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA224(null);
        }

        [BenchmarkCategory("SHA224"), Benchmark(OperationsPerInvoke = 4)]
        public byte[][] SHA224_MultiHash_EmptyInput()
        {
            return HashFunctions.SHA224Parallel(null, null, null, null);
        }

        [BenchmarkCategory("SHA512"), Benchmark(Baseline = true)]
        public byte[] Native_SHA512_SingleHash_EmptyInput()
        {
            return NativeSHA512.ComputeHash(Array.Empty<byte>());
        }

        [BenchmarkCategory("SHA512"), Benchmark]
        public byte[] SHA512_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA512(null);
        }

        [BenchmarkCategory("SHA512"), Benchmark(OperationsPerInvoke = 2)]
        public byte[][] SHA512_MultiHash_2_EmptyInput()
        {
            return HashFunctions.SHA512Parallel(null, null);
        }

        [BenchmarkCategory("SHA512"), Benchmark(OperationsPerInvoke = 4)]
        public byte[][] SHA512_MultiHash_4_EmptyInput()
        {
            return HashFunctions.SHA512Parallel(null, null, null, null);
        }

        [BenchmarkCategory("SHA384"), Benchmark(Baseline = true)]
        public byte[] SHA384_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA384(null);
        }

        [BenchmarkCategory("SHA384"), Benchmark(OperationsPerInvoke = 2)]
        public byte[][] SHA384_MultiHash_2_EmptyInput()
        {
            return HashFunctions.SHA384Parallel(null, null);
        }

        [BenchmarkCategory("SHA384"), Benchmark(OperationsPerInvoke = 4)]
        public byte[][] SHA384_MultiHash_4_EmptyInput()
        {
            return HashFunctions.SHA384Parallel(null, null, null, null);
        }

        static void Main(string[] args)
        {
            BenchmarkRunner.Run<HashAlgorithmBenchmarks>();
        }
    }
}
