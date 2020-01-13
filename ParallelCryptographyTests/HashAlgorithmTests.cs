using System;
using System.Text;
using System.Threading;
using Xunit;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography.Tests
{
    public class HashAlgorithmTests
    {
        const string MD5Empty = "d41d8cd98f00b204e9800998ecf8427e";
        const string SHA1Empty = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        const string SHA256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        const string SHA224Empty = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
        const string SHA512Empty = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        const string SHA384Empty = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";


        [Fact]
        public void MD5()
        {
            var hash = HashFunctions.MD5(null);
            Assert.Equal(MD5Empty, MakeHashString(hash));
        }

        [Fact]
        public void SHA1()
        {
            var hash = HashFunctions.SHA1(null);
            Assert.Equal(SHA1Empty, MakeHashString(hash));
        }

        [Fact]
        public void SHA256()
        {
            var hash = HashFunctions.SHA256(null);
            Assert.Equal(SHA256Empty, MakeHashString(hash));
        }

        [Fact]
        public void SHA224()
        {
            var hash = HashFunctions.SHA224(null);
            Assert.Equal(SHA224Empty, MakeHashString(hash));
        }

        [Fact]
        public void SHA512()
        {
            var hash = HashFunctions.SHA512(null);
            Assert.Equal(SHA512Empty, MakeHashString(hash));
        }

        [Fact]
        public void SHA384()
        {
            var hash = HashFunctions.SHA384(null);
            Assert.Equal(SHA384Empty, MakeHashString(hash));
        }

        [Sse2IsSupportedFact]
        public void MD5Parallel()
        {
            ParallelTest((Func<byte[], byte[], byte[], byte[], byte[][]>)HashFunctions.MD5Parallel, HashFunctions.MD5);
        }

        [Avx2IsSupportedFact]
        public void MD5Parallel_Avx2()
        {
            ParallelTest((Func<byte[], byte[], byte[], byte[], byte[], byte[], byte[], byte[], byte[][]>)HashFunctions.MD5Parallel, HashFunctions.MD5);
        }

        [Sse2IsSupportedFact]
        public void SHA1Parallel()
        {
            ParallelTest(HashFunctions.SHA1Parallel, HashFunctions.SHA1);
        }

        [Sse2IsSupportedFact]
        public void Sha256Parallel()
        {
            ParallelTest(HashFunctions.SHA256Parallel, HashFunctions.SHA256);
        }

        [Sse2IsSupportedFact]
        public void Sha224Parallel()
        {
            ParallelTest(HashFunctions.SHA224Parallel, HashFunctions.SHA224);
        }

        [Sse2IsSupportedFact]
        public void Sha512Parallel()
        {
            ParallelTest((Func<byte[], byte[], byte[][]>)HashFunctions.SHA512Parallel, HashFunctions.SHA512);
        }

        [Avx2IsSupportedFact]
        public void Sha512Parallel_AVX2()
        {
            ParallelTest((Func<byte[], byte[], byte[], byte[], byte[][]>)HashFunctions.SHA512Parallel, HashFunctions.SHA512);
        }

        [Sse2IsSupportedFact]
        public void Sha384Parallel_2()
        {
            Func<byte[], byte[], byte[][]> parallel = HashFunctions.SHA384Parallel;
            ParallelTest(parallel, HashFunctions.SHA384);
        }

        [Avx2IsSupportedFact]
        public void Sha384Parallel_4()
        {
            Func<byte[], byte[], byte[], byte[], byte[][]> parallel = HashFunctions.SHA384Parallel;
            ParallelTest(parallel, HashFunctions.SHA384);
        }

        private static void ParallelTest(Func<byte[], byte[], byte[], byte[], byte[], byte[], byte[], byte[], byte[][]> parallelHash, Func<byte[], byte[]> scalar)
        {
            var res = parallelHash(null, null, null, null, null, null, null, null);
            var actual = scalar(null);

            Assert.Equal(actual, res[0]);

            for (int i = 1; i < 8; ++i)
            {
                Assert.Equal(actual, res[i]);
            }

            var rng = new Random();

            byte[][] data = new byte[8][];
            int len = 64;

            for (int i = 0; i < 8; ++i)
            {
                var tmp = new byte[len];
                rng.NextBytes(tmp);
                data[i] = tmp;
                len *= 2;
            }

            var hashes = parallelHash(data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);

            for (int i = 0; i < 8; ++i)
            {
                Assert.Equal(scalar(data[i]), hashes[i]);
            }
        }

        private static void ParallelTest(Func<byte[], byte[], byte[], byte[], byte[][]> parallelHash, Func<byte[], byte[]> scalar)
        {
            var res = parallelHash(null, null, null, null);
            var actual = scalar(null);

            Assert.Equal(actual, res[0]);

            for (int i = 1; i < 4; ++i)
            {
                Assert.Equal(actual, res[i]);
            }

            var rng = new Random();

            byte[] arr1, arr2, arr3, arr4;

            arr1 = new byte[64];
            arr2 = new byte[128];
            arr3 = new byte[256];
            arr4 = new byte[512];

            rng.NextBytes(arr1);
            rng.NextBytes(arr2);
            rng.NextBytes(arr3);
            rng.NextBytes(arr4);

            res = parallelHash(arr1, arr2, arr3, arr4);

            Assert.Equal(scalar(arr1), res[0]);
            Assert.Equal(scalar(arr2), res[1]);
            Assert.Equal(scalar(arr3), res[2]);
            Assert.Equal(scalar(arr4), res[3]);
        }

        private static void ParallelTest(Func<byte[], byte[], byte[][]> parallelHash, Func<byte[], byte[]> scalar)
        {
            var res = parallelHash(null, null);
            var actual = scalar(null);

            Assert.Equal(actual, res[0]);
            Assert.Equal(actual, res[1]);

            var rng = new Random();

            byte[] arr1, arr2;

            arr1 = new byte[128];
            arr2 = new byte[512];

            rng.NextBytes(arr1);
            rng.NextBytes(arr2);

            res = parallelHash(arr1, arr2);

            Assert.Equal(scalar(arr1), res[0]);
            Assert.Equal(scalar(arr2), res[1]);
        }

        private static string MakeHashString(byte[] hash)
        {
            var builder = localBuilder.Value;

            for (int i = 0; i < hash.Length; ++i)
            {
                byte b = hash[i];
                builder.Append(chars[b >> 4]);
                builder.Append(chars[b & 15]);
            }

            var tmp = builder.ToString();
            builder.Clear();
            return tmp;
        }

        private static readonly char[] chars = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        private static readonly ThreadLocal<StringBuilder> localBuilder = new ThreadLocal<StringBuilder>(() => new StringBuilder());
    }
}
