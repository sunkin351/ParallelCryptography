using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

namespace ParallelCryptography.Benchmarks
{
    public class HashAlgorithmBenchmarks
    {
        MD5 NativeMD5;
        SHA1 NativeSHA1;
        SHA256 NativeSHA256;

        SHA1Managed Sha1;
        SHA256Managed Sha256;

        [GlobalSetup]
        public void Init()
        {
            NativeMD5 = MD5.Create();
            NativeSHA1 = SHA1.Create();
            NativeSHA256 = SHA256.Create();
            Sha1 = new SHA1Managed();
            Sha256 = new SHA256Managed();
        }



        [Benchmark]
        public byte[] Native_MD5_SingleHash_EmptyInput()
        {
            return NativeMD5.ComputeHash(Array.Empty<byte>());
        }

        [Benchmark]
        public byte[] MD5_SingleHash_EmptyInput()
        {
            return HashFunctions.MD5(null);
        }

        [Benchmark]
        public byte[][] MD5_MultiHash_EmptyInput()
        {
            return HashFunctions.MD5Parallel(null, null, null, null);
        }

        [Benchmark]
        public byte[] Native_SHA1_SingleHash_EmptyInput()
        {
            return NativeSHA1.ComputeHash(Array.Empty<byte>());
        }

        [Benchmark]
        public byte[] SHA1_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA1(null);
        }

        [Benchmark]
        public byte[][] SHA1_MultiHash_EmptyInput()
        {
            return HashFunctions.SHA1Parallel(null, null, null, null);
        }

        [Benchmark]
        public byte[] Native_SHA256_SingleHash_EmptyInput()
        {
            return NativeSHA256.ComputeHash(Array.Empty<byte>());
        }

        [Benchmark]
        public byte[] SHA256_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA256(null);
        }

        [Benchmark]
        public byte[][] SHA256_MultiHash_EmptyInput()
        {
            return HashFunctions.SHA256Parallel(null, null, null, null);
        }

        [Benchmark]
        public byte[] SHA224_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA224(null);
        }

        [Benchmark]
        public byte[][] SHA224_MultiHash_EmptyInput()
        {
            return HashFunctions.SHA224Parallel(null, null, null, null);
        }

        static void Main(string[] args)
        {
            BenchmarkRunner.Run<HashAlgorithmBenchmarks>();
        }
    }
}
