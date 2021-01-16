using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography
{
    public static unsafe partial class HashFunctions
    {
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        [SkipLocalsInit]
        public static byte[] SHA1(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            uint* state = stackalloc uint[5]
            {
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0
            };

            uint* schedule = stackalloc uint[80];

            do
            {
                ctx.PrepareBlock((byte*)schedule, sizeof(uint) * 16);
                InitScheduleSHA1(schedule);
                ProcessBlockSHA1(state, schedule);
            }
            while (!ctx.Complete);

            //Byte order correction
            if (BitConverter.IsLittleEndian)
            {
                byte[] hash = new byte[5 * sizeof(uint)];

                fixed (byte* phash = hash)
                {
                    ReverseEndianess(state, (uint*)phash, 5);
                }

                return hash;
            }
            else
            {
                return new Span<byte>(state, 5 * sizeof(uint)).ToArray();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        [SkipLocalsInit]
        public static unsafe byte[][] SHA1Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException(SSE2_NotAvailable);
            }

            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
            }

            Vector128<uint>* state = stackalloc Vector128<uint>[5]
            {
                Vector128.Create(0x67452301u),
                Vector128.Create(0xEFCDAB89u),
                Vector128.Create(0x98BADCFEu),
                Vector128.Create(0x10325476u),
                Vector128.Create(0xC3D2E1F0u)
            };

            bool* flags = stackalloc bool[4];
            Unsafe.InitBlock(flags, 0, 4);

            SHADataContext[] contexts = new SHADataContext[4]
            {
                new SHADataContext(data1),
                new SHADataContext(data2),
                new SHADataContext(data3),
                new SHADataContext(data4)
            };

            uint* blocks = stackalloc uint[16 * 4];

            Vector128<uint>* schedule = stackalloc Vector128<uint>[80];

            byte[][] hashes = AllocateHashs(4, sizeof(uint) * 5);

            int concurrentHashes = 4, i;

            do
            {
                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock((byte*)(blocks + i * 16), sizeof(uint) * 16);
                    }
                }

                InitScheduleSHA1Parallel(schedule, blocks);

                ProcessBlocksParallelSHA1(state, schedule);

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        fixed (byte* pHash = hashes[i])
                        {
                            ExtractHashState_SHA1(state, (uint*)pHash, i);
                        }

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 2);

            if (concurrentHashes > 0)
            {
                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                        continue;

                    fixed (byte* pHash = hashes[i])
                    {
                        ExtractHashState_SHA1(state, (uint*)pHash, i);

                        do
                        {
                            ctx.PrepareBlock((byte*)schedule, sizeof(uint) * 16);

                            InitScheduleSHA1((uint*)schedule);

                            ProcessBlockSHA1((uint*)pHash, (uint*)schedule);

                        } while (!ctx.Complete);
                    }
                }
            }

            //Hash byte order correction
            if (BitConverter.IsLittleEndian)
            {
                foreach (var hash in hashes)
                {
                    fixed (byte* phash = hash)
                        ReverseEndianess((uint*)phash, 5);
                }
            }

            return hashes;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void InitScheduleSHA1(uint* schedule)
        {
            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(schedule, 16);
            }

            if (Sse2.IsSupported)
            {
                int i = 16;

                while (i < 80)
                {
                    Vector128<uint> tmp, tmp2;

                    tmp = Sse2.LoadVector128(schedule + (i - 16));
                    tmp = Sse2.Xor(tmp, Sse2.LoadVector128(schedule + (i - 14)));
                    tmp = Sse2.Xor(tmp, Sse2.LoadVector128(schedule + (i - 8)));

                    if (Avx2.IsSupported)
                    {
                        tmp2 = Avx2.MaskLoad(schedule + (i - 3), LoadMask);
                    }
                    else
                    {
                        tmp2 = Sse2.LoadVector128(schedule + (i - 3));
                        tmp2 = Sse2.And(tmp2, LoadMask);
                    }

                    tmp = Sse2.Xor(tmp, tmp2);

                    //RotateLeft(tmp, 1)
                    tmp2 = Sse2.ShiftRightLogical(tmp, 31);
                    tmp = Sse2.ShiftLeftLogical(tmp, 1);
                    tmp = Sse2.Or(tmp, tmp2);

                    //complete the result for the last element
                    if (Sse41.IsSupported)
                    {
                        uint val = Sse2.ConvertToUInt32(tmp);
                        val = BitOperations.RotateLeft(val, 1) ^ Sse41.Extract(tmp, 3);

                        tmp = Sse41.Insert(tmp, val, 3);

                        Sse2.Store(schedule + i, tmp);
                    }
                    else
                    {
                        Sse2.Store(schedule + i, tmp);

                        schedule[i + 3] = BitOperations.RotateLeft(schedule[i], 1) ^ schedule[i + 3];
                    }

                    i += 4;
                }
            }
            else
            {
                for (int i = 16; i < 80; ++i)
                {
                    schedule[i] = BitOperations.RotateLeft(schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16], 1);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void InitScheduleSHA1Parallel(Vector128<uint>* schedule, uint* block)
        {
            if (Avx2.IsSupported)
            {
                for (int i = 0; i < 16; ++i)
                {
                    var idx = Vector128.Create(i);
                    idx = Sse2.Add(idx, GatherIndex_32_128);

                    var vec = Avx2.GatherVector128(block, idx, 4);

                    vec = Ssse3.Shuffle(vec.AsByte(), ReverseEndianess_32_128).AsUInt32();

                    schedule[i] = vec;
                }
            }
            else
            {
                uint* scheduleptr = (uint*)schedule;

                for (int i = 0; i < 16; ++i)
                {
                    var tptr = scheduleptr + (i * 4);

                    tptr[0] = BinaryPrimitives.ReverseEndianness(block[i]);
                    tptr[1] = BinaryPrimitives.ReverseEndianness(block[i + 16]);
                    tptr[2] = BinaryPrimitives.ReverseEndianness(block[i + 16 * 2]);
                    tptr[3] = BinaryPrimitives.ReverseEndianness(block[i + 16 * 3]);
                }
            }

            for (int i = 16; i < 80; ++i)
            {
                var res = schedule[i - 16];
                res = Sse2.Xor(res, schedule[i - 14]);
                res = Sse2.Xor(res, schedule[i - 8]);
                res = Sse2.Xor(res, schedule[i - 3]);

                var rolltmp = Sse2.ShiftRightLogical(res, 31);
                res = Sse2.ShiftLeftLogical(res, 1);
                res = Sse2.Or(res, rolltmp);

                schedule[i] = res;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static void ProcessBlockSHA1(uint* state, uint* chunk)
        {
            uint a, b, c, d, e;
            int idx;

            a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

            unchecked
            {
                for (idx = 0; idx < 20; ++idx)
                {
                    const uint k = 0x5A827999;
                    uint f = d ^ (b & (c ^ d));

                    var t = BitOperations.RotateLeft(a, 5) + f + e + k + chunk[idx];
                    e = d;
                    d = c;
                    c = BitOperations.RotateLeft(b, 30);
                    b = a;
                    a = t;
                }

                for (; idx < 40; ++idx)
                {
                    const uint k = 0x6ED9EBA1;
                    uint f = b ^ c ^ d;

                    var t = BitOperations.RotateLeft(a, 5) + f + e + k + chunk[idx];
                    e = d;
                    d = c;
                    c = BitOperations.RotateLeft(b, 30);
                    b = a;
                    a = t;
                }

                for (; idx < 60; ++idx)
                {
                    const uint k = 0x8F1BBCDC;
                    uint f = (b & c) | (b & d) | (c & d);

                    var t = BitOperations.RotateLeft(a, 5) + f + e + k + chunk[idx];
                    e = d;
                    d = c;
                    c = BitOperations.RotateLeft(b, 30);
                    b = a;
                    a = t;
                }

                for (; idx < 80; ++idx)
                {
                    const uint k = 0xCA62C1D6;
                    uint f = b ^ c ^ d;

                    var t = BitOperations.RotateLeft(a, 5) + f + e + k + chunk[idx];
                    e = d;
                    d = c;
                    c = BitOperations.RotateLeft(b, 30);
                    b = a;
                    a = t;
                }

                state[0] += a;
                state[1] += b;
                state[2] += c;
                state[3] += d;
                state[4] += e;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void ProcessBlocksParallelSHA1(Vector128<uint>* state, Vector128<uint>* schedule)
        {
            Vector128<uint> a, b, c, d, e;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];

            int i = 0;

            Vector128<uint> f, t, k;
            k = Vector128.Create(0x5A827999u);

            while (i < 20)
            {
                t = Sse2.Xor(c, d);
                t = Sse2.And(t, b);
                t = Sse2.Xor(t, d);

                t = Sse2.Add(t, schedule[i]);
                t = Sse2.Add(t, e);
                t = Sse2.Add(t, k);
                t = Sse2.Add(t, RotateLeft5(a));

                e = d;
                d = c;
                c = RotateLeft30(b);
                b = a;
                a = t;

                i += 1;
            }

            k = Vector128.Create(0x6ED9EBA1u);

            while (i < 40)
            {
                t = Sse2.Xor(b, c);
                t = Sse2.Xor(t, d);

                t = Sse2.Add(t, schedule[i]);
                t = Sse2.Add(t, e);
                t = Sse2.Add(t, k);
                t = Sse2.Add(t, RotateLeft5(a));

                e = d;
                d = c;
                c = RotateLeft30(b);
                b = a;
                a = t;

                i += 1;
            }

            k = Vector128.Create(0x8F1BBCDCu);

            while (i < 60)
            {
                t = Sse2.And(b, c);
                t = Sse2.Or(t, Sse2.And(b, d));
                t = Sse2.Or(t, Sse2.And(c, d));

                t = Sse2.Add(t, schedule[i]);
                t = Sse2.Add(t, k);
                t = Sse2.Add(t, e);
                t = Sse2.Add(t, RotateLeft5(a));

                e = d;
                d = c;
                c = RotateLeft30(b);
                b = a;
                a = t;

                i += 1;
            }

            k = Vector128.Create(0xCA62C1D6u);

            while (i < 80)
            {
                t = Sse2.Xor(b, c);
                t = Sse2.Xor(t, d);

                t = Sse2.Add(t, schedule[i]);
                t = Sse2.Add(t, e);
                t = Sse2.Add(t, k);
                t = Sse2.Add(t, RotateLeft5(a));

                e = d;
                d = c;
                c = RotateLeft30(b);
                b = a;
                a = t;

                i += 1;
            }

            state[0] = Sse2.Add(a, state[0]);
            state[1] = Sse2.Add(b, state[1]);
            state[2] = Sse2.Add(c, state[2]);
            state[3] = Sse2.Add(d, state[3]);
            state[4] = Sse2.Add(e, state[4]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> RotateLeft5(Vector128<uint> vec)
        {
            var tmp = Sse2.ShiftLeftLogical(vec, 5);
            vec = Sse2.ShiftRightLogical(vec, 32 - 5);
            return Sse2.Or(tmp, vec);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> RotateLeft30(Vector128<uint> vec)
        {
            var tmp = Sse2.ShiftLeftLogical(vec, 30);
            vec = Sse2.ShiftRightLogical(vec, 32 - 30);
            return Sse2.Or(tmp, vec);
        }

        private static void ExtractHashState_SHA1(Vector128<uint>* state, uint* hash, int hashIdx)
        {
            Debug.Assert((uint)hashIdx < (uint)Vector128<uint>.Count);

            uint* stateScalar = (uint*)state;

            for (int i = 0; i < 5; ++i)
            {
                hash[i] = stateScalar[Vector128<uint>.Count * i + hashIdx];
            }
        }
    }
}
