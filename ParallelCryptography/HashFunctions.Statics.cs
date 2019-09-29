using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography
{
    public static partial class HashFunctions
    {
        private static void ReverseEndianess(Span<uint> span)
        {
            int i = 0;

            if (Ssse3.IsSupported && span.Length >= 4)
            {
                var vecSpan = MemoryMarshal.Cast<uint, Vector128<uint>>(span);
                for (; i < vecSpan.Length; ++i)
                {
                    vecSpan[i] = Ssse3.Shuffle(vecSpan[i].AsByte(), EndianessReverseShuffleConstant).AsUInt32();
                }

                if ((span.Length & 3) == 0)
                    return;

                i *= 4;
            }

            for (; i < span.Length; ++i)
            {
                span[i] = BinaryPrimitives.ReverseEndianness(span[i]);
            }
        }

        private static void ReverseEndianess(Span<ulong> span)
        {
            for(int i = 0; i < span.Length; ++i)
            {
                span[i] = BinaryPrimitives.ReverseEndianness(span[i]);
            }
        }

        private static byte[][] AllocateHashs(int hashCount, int hashLength)
        {
            var res = new byte[hashCount][];
            for (int i = 0; i < hashCount; ++i)
            {
                res[i] = new byte[hashLength];
            }
            return res;
        }

        private static void ExtractHashFromState(Span<Vector128<uint>> state, Span<uint> hash, int hashIdx)
        {
            Debug.Assert((uint)hashIdx < 4u, "'hashIdx' is outside the acceptable range");

            Span<uint> stateScalar = MemoryMarshal.Cast<Vector128<uint>, uint>(state);

            var length = Math.Min(hash.Length, state.Length);

            for (int i = 0; i < length; ++i)
            {
                hash[i] = stateScalar[4 * i + hashIdx];
            }
        }

        static HashFunctions()
        {
        }

        private static readonly Vector128<uint> AllBitsSet = Vector128.Create(uint.MaxValue);

        //MD5 statics
        private static readonly uint[] MD5TableK = new uint[]
        {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };

        private static readonly int[] MD5ShiftConsts = new int[]
        {
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        };

        private static readonly Vector128<int> MD5GatherIndex = Vector128.Create(0, 16, 16 * 2, 16 * 3);


        //SHA1 statics
        private static readonly MemoryPool<uint> MemoryPool = MemoryPool<uint>.Shared;

        private static readonly Vector128<int> SHA1GatherIndex = Vector128.Create(0, 80, 80 * 2, 80 * 3);
        private static readonly Vector128<byte> EndianessReverseShuffleConstant = Vector128.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
        private static readonly Vector128<uint> LoadMask = Vector128.Create(uint.MaxValue, uint.MaxValue, uint.MaxValue, 0);
        private static readonly uint[] SHA1InitState = new uint[5] { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

        //SHA2 statics

        private static readonly uint[] SHA256TableK = new uint[]
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        private static readonly Vector128<int> Sha256GatherIndex = Vector128.Create(0, 64, 64 * 2, 64 * 3);

        private static readonly ulong[] SHA512TableK = new ulong[]
        {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };


        [StructLayout(LayoutKind.Auto)]
        private struct SHADataContext
        {
            byte[] _data;
            int _dataidx;
            ulong _bitsize;
            bool appended;

            public bool Complete { get; private set; }

            public SHADataContext(byte[] data)
            {
                _data = data;
                _bitsize = data == null ? 0 : (ulong)data.Length * 8;
                _dataidx = 0;
                appended = false;
                Complete = false;
            }

            [MethodImpl(MethodImplOptions.AggressiveOptimization)]
            public void PrepareBlock(Span<byte> span)
            {
                Debug.Assert(span.Length == 64 || span.Length == 128);

                int len = Math.Min(span.Length, Length() - _dataidx);

                if (len == 0)
                {
                    span.Clear();

                    if (!appended)
                    {
                        span[0] = 0x80;
                        appended = true;
                    }

                    WriteBitsize(span);
                    Complete = true;
                    return;
                }

                _data.AsSpan(_dataidx, len).CopyTo(span);
                _dataidx += len;

                if (len != span.Length)
                {
                    span.Slice(len).Clear();
                }

                if (_dataidx == _data.Length)
                {
                    int spaceLeft = span.Length - len;

                    if (spaceLeft > 0)
                    {
                        span[len] = 0x80;
                        appended = true;

                        if (spaceLeft - 1 >= 8)
                        {
                            WriteBitsize(span);
                            Complete = true;
                        }
                    }
                }
            }

            private int Length()
            {
                return _data?.Length ?? 0;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private void WriteBitsize(Span<byte> span)
            {
                BinaryPrimitives.WriteUInt64BigEndian(span.Slice(span.Length - sizeof(ulong)), _bitsize);
            }
        }
    }
}
