using System;
using System.Text;
using Xunit;
using System.Threading;

using ParallelCryptography;


namespace ParallelCryptography.Tests
{
    public class MainHashFunctionTests
    {
        const string MD5Empty = "d41d8cd98f00b204e9800998ecf8427e";
        const string SHA1Empty = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        const string SHA256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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
            var hasharray = HashFunctions.SHA256(null);

            Assert.NotNull(hasharray);

            string hash = MakeHashString(hasharray);

            Assert.Equal(SHA256Empty, hash);
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
