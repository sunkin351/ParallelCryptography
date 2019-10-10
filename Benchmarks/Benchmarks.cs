﻿using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

namespace ParallelCryptography.Benchmarks
{
    [CoreJob]
    public class HashAlgorithmBenchmarks
    {
        MD5 NativeMD5;
        SHA1 NativeSHA1;
        SHA256 NativeSHA256;
        SHA512 NativeSHA512;

        SHA1Managed Sha1;
        SHA256Managed Sha256;

        [GlobalSetup]
        public void Init()
        {
            NativeMD5 = MD5.Create();
            NativeSHA1 = SHA1.Create();
            NativeSHA256 = SHA256.Create();
            NativeSHA512 = SHA512.Create();
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

        [Benchmark(OperationsPerInvoke = 4)]
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

        [Benchmark(OperationsPerInvoke = 4)]
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

        [Benchmark(OperationsPerInvoke = 4)]
        public byte[][] SHA256_MultiHash_EmptyInput()
        {
            return HashFunctions.SHA256Parallel(null, null, null, null);
        }

        [Benchmark]
        public byte[] SHA224_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA224(null);
        }

        [Benchmark(OperationsPerInvoke = 4)]
        public byte[][] SHA224_MultiHash_EmptyInput()
        {
            return HashFunctions.SHA224Parallel(null, null, null, null);
        }

        [Benchmark]
        public byte[] Native_SHA512_SingleHash_EmptyInput()
        {
            return NativeSHA512.ComputeHash(Array.Empty<byte>());
        }

        [Benchmark]
        public byte[] SHA512_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA512(null);
        }

        [Benchmark(OperationsPerInvoke = 2)]
        public byte[][] SHA512_MultiHash_2_EmptyInput()
        {
            return HashFunctions.SHA512Parallel(null, null);
        }

        [Benchmark(OperationsPerInvoke = 4)]
        public byte[][] SHA512_MultiHash_4_EmptyInput()
        {
            return HashFunctions.SHA512Parallel(null, null, null, null);
        }

        [Benchmark]
        public byte[] SHA384_SingleHash_EmptyInput()
        {
            return HashFunctions.SHA384(null);
        }

        [Benchmark(OperationsPerInvoke = 2)]
        public byte[][] SHA384_MultiHash_2_EmptyInput()
        {
            return HashFunctions.SHA384Parallel(null, null);
        }

        [Benchmark(OperationsPerInvoke = 4)]
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
