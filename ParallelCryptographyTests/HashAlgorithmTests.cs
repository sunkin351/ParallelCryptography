using System;
using System.Text;
using System.Threading;
using Xunit;

namespace ParallelCryptography.Tests
{
    public class HashAlgorithmTests
    {
        const string MD5Empty = "d41d8cd98f00b204e9800998ecf8427e";
        const string SHA1Empty = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        const string SHA256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        const string SHA224Empty = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
        const string SHA512Empty = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";


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
            var hash = HashFunctions.Sha512(null);
            Assert.Equal(SHA512Empty, MakeHashString(hash));
        }

        [Fact]
        public void MD5Parallel()
        {
            ParallelTest(HashFunctions.MD5Parallel, HashFunctions.MD5);
        }

        [Fact]
        public void SHA1Parallel()
        {
            ParallelTest(HashFunctions.SHA1Parallel, HashFunctions.SHA1);
        }

        [Fact]
        public void Sha256Parallel()
        {
            ParallelTest(HashFunctions.SHA256Parallel, HashFunctions.SHA256);
        }

        [Fact]
        public void Sha224Parallel()
        {
            ParallelTest(HashFunctions.SHA224Parallel, HashFunctions.SHA224);
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

            arr1 = new byte[31];
            arr2 = new byte[63];
            arr3 = new byte[127];
            arr4 = new byte[255];

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
