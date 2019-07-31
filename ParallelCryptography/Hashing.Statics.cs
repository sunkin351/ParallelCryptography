using System;
using System.Buffers.Binary;
using System.Buffers;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Diagnostics;

namespace ParallelCryptography
{
    public static partial class HashFunctions
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void ReverseEndianess(Span<uint> span)
        {
            if (Ssse3.IsSupported && span.Length % 4 == 0)
            {
                var vecSpan = MemoryMarshal.Cast<uint, Vector128<uint>>(span);
                for(int i = 0; i < vecSpan.Length; ++i)
                {
                    vecSpan[i] = Ssse3.Shuffle(vecSpan[i].AsByte(), EndianessReverseShuffleConstant).AsUInt32();
                }
            }
            else
            {
                for (int i = 0; i < span.Length; ++i)
                {
                    span[i] = BinaryPrimitives.ReverseEndianness(span[i]);
                }
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
            Debug.Assert(state.Length == hash.Length);
            Debug.Assert((uint)hashIdx < 4u, "'hashIdx' is outside the acceptable range");

            Span<uint> stateScalar = MemoryMarshal.Cast<Vector128<uint>, uint>(state);

            for (int i = 0; i < hash.Length; ++i)
            {
                hash[i] = stateScalar[4 * i + hashIdx];
            }
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
                Debug.Assert(span.Length == 64);

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

                if (len != 64)
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
