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
        [SkipLocalsInit]
        public static byte[] MD5(byte[] data)
        {
            //MD5 formats its data in the same way SHA1 and SHA2 do.
            SHADataContext ctx = new SHADataContext(data);

            //MD5 initial hash state
            uint* state = stackalloc uint[4]
            {
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476
            };

            //MD5 schedule memory
            uint* schedule = stackalloc uint[16];

            do
            {
                //Prepare first/next block
                ctx.PrepareBlock((byte*)schedule, sizeof(uint) * 16);

                if (!BitConverter.IsLittleEndian) //If big endian, reverse data endianess
                {
                    ReverseEndianess(schedule, 16);
                }

                //Process data into hash state
                ProcessBlockMD5(state, schedule);
            }
            while (!ctx.Complete);

            //Hash byte order correction
            if (!BitConverter.IsLittleEndian)
            {
                //fast path removes a copy on big endian platforms

                byte[] hash = new byte[sizeof(uint) * 4];

                fixed (byte* pHash = hash)
                {
                    StateCopyReversed_MD5(state, pHash);
                }

                return hash;
            }
            else
            {
                return new Span<byte>(state, sizeof(uint) * 4).ToArray();
            }
        }

        [SkipLocalsInit]
        public static unsafe byte[][] MD5Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException(SSE2_NotAvailable);
            }

            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
            }

            const int HashSize = sizeof(uint) * 4;

            SHADataContext[] ctxArr = new SHADataContext[4]
            {
                new SHADataContext(data1),
                new SHADataContext(data2),
                new SHADataContext(data3),
                new SHADataContext(data4)
            };

            byte[][] hashes = AllocateHashs(4, HashSize);

            Vector128<uint>* state = stackalloc Vector128<uint>[4]
            {
                Vector128.Create(0x67452301u),
                Vector128.Create(0xefcdab89u),
                Vector128.Create(0x98badcfeu),
                Vector128.Create(0x10325476u)
            };

            bool* flags = stackalloc bool[Vector128<uint>.Count];
            Unsafe.InitBlock(flags, 0, 4); //Assuming 4 bytes, aligned

            uint* blocksPtr = stackalloc uint[16 * Vector128<uint>.Count];

            Vector128<uint>* schedule = stackalloc Vector128<uint>[16];

            int concurrentHashes = 4;

            do
            {
                for (int i = 0; i < Vector128<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock((byte*)(blocksPtr + i * 16), sizeof(uint) * 16);
                    }
                }

                TransformParallelSchedule(schedule, blocksPtr);

                ProcessBlocksParallelMD5(state, schedule);

                for (int i = 0; i < Vector128<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        fixed (byte* pHash = hashes[i])
                        {
                            ExtractHashState_MD5(state, (uint*)pHash, i);
                        }

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 2);

            if (concurrentHashes > 0)
            {
                for (int i = 0; i < Vector128<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (ctx.Complete)
                        continue;

                    fixed (byte* pHash = hashes[i])
                    {
                        ExtractHashState_MD5(state, (uint*)pHash, i);

                        do
                        {
                            ctx.PrepareBlock((byte*)blocksPtr, sizeof(uint) * 16);

                            ProcessBlockMD5((uint*)pHash, blocksPtr);
                        }
                        while (!ctx.Complete);
                    }
                }
            }

            return hashes;
        }

        [SkipLocalsInit]
        public static unsafe byte[][] MD5Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4, byte[] data5, byte[] data6, byte[] data7, byte[] data8)
        {
            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException(SSE2_NotAvailable);
            }

            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
            }

            const int HashSize = sizeof(uint) * 4;

            SHADataContext[] ctxArr = new SHADataContext[8]
            {
                new SHADataContext(data1),
                new SHADataContext(data2),
                new SHADataContext(data3),
                new SHADataContext(data4),
                new SHADataContext(data5),
                new SHADataContext(data6),
                new SHADataContext(data7),
                new SHADataContext(data8)
            };

            byte[][] hashes = AllocateHashs(Vector256<uint>.Count, HashSize);

            Vector256<uint>* state = stackalloc Vector256<uint>[4]
            {
                Vector256.Create(0x67452301u),
                Vector256.Create(0xefcdab89u),
                Vector256.Create(0x98badcfeu),
                Vector256.Create(0x10325476u)
            };

            bool* flags = stackalloc bool[Vector256<uint>.Count];
            Unsafe.InitBlock(flags, 0, 8);

            uint* blocks = stackalloc uint[16 * Vector256<uint>.Count];

            //Span<uint> blocks = new Span<uint>(blocksPtr, 16 * Vector256<uint>.Count);
            Vector256<uint>* schedule = stackalloc Vector256<uint>[16];

            int concurrentHashes = 4;

            do
            {
                for (int i = 0; i < Vector256<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (ctx.Complete)
                        continue;

                    ctx.PrepareBlock((byte*)(blocks + i * 16), sizeof(uint) * 16);
                }

                TransformParallelSchedule(schedule, blocks);

                ProcessBlocksParallelMD5(state, schedule);

                for (int i = 0; i < Vector256<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        fixed (byte* pHash = hashes[i])
                        {
                            ExtractHashState_MD5(state, (uint*)pHash, i);
                        }

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 2);

            if (concurrentHashes > 0)
            {
                for (int i = 0; i < Vector256<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (ctx.Complete)
                        continue;

                    Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);

                    fixed (uint* pHash = hash)
                    {
                        ExtractHashState_MD5(state, pHash, i);
                        
                        do
                        {
                            ctx.PrepareBlock((byte*)blocks, sizeof(uint) * 16);

                            ProcessBlockMD5(pHash, blocks);
                        }
                        while (!ctx.Complete);
                    }
                }
            }

            return hashes;
        }

        private static void ProcessBlockMD5(uint* state, uint* schedule)
        {
            uint a, b, c, d;
            uint f;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            
            int i = 0;
            while (i < 16)
            {
                f = (b & c) | (~b & d);

                f += a + MD5TableK[i] + schedule[i];
                a = d;
                d = c;
                c = b;
                b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                i += 1;
            }

            while (i < 32)
            {
                f = (d & b) | (~d & c);

                f += a + MD5TableK[i] + schedule[(5 * i + 1) & 15];
                a = d;
                d = c;
                c = b;
                b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                i += 1;
            }

            while (i < 48)
            {
                f = b ^ c ^ d;

                f += a + MD5TableK[i] + schedule[(3 * i + 5) & 15];
                a = d;
                d = c;
                c = b;
                b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                i += 1;
            }

            while (i < 64)
            {
                f = c ^ (b | ~d);

                f += a + MD5TableK[i] + schedule[(7 * i) & 15];
                a = d;
                d = c;
                c = b;
                b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                i += 1;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
        }

        private static unsafe void ProcessBlocksParallelMD5(Vector128<uint>* state, Vector128<uint>* schedule)
        {
            Vector128<uint> a, b, c, d;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];

            fixed (uint* tableK = MD5TableK)
            fixed (int* shiftConstants = MD5ShiftConsts)
            {
                int i = 0;
                Vector128<int> g;
                Vector128<uint> f, h, t;

                while (i < 16)
                {
                    int idx = i;
                    //f = (b & c) | (~b & d);
                    f = Sse2.AndNot(b, d);
                    f = Sse2.Or(f, Sse2.And(b, c));

                    //f += a + MD5TableK[i] + schedule[g];
                    if (Avx2.IsSupported)
                    {
                        t = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        t = Vector128.Create(tableK[i]);
                    }
                    t = Sse2.Add(t, a);
                    t = Sse2.Add(t, schedule[idx]);
                    f = Sse2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    var vtmp = LeftRotate(f, shiftConstants[i]);
                    b = Sse2.Add(b, vtmp);

                    i += 1;
                }

                while (i < 32)
                {
                    int idx = (5 * i + 1) & 15;

                    f = Sse2.And(d, b);
                    f = Sse2.Or(f, Sse2.AndNot(d, c));

                    if (Avx2.IsSupported)
                    {
                        t = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        t = Vector128.Create(tableK[i]);
                    }
                    t = Sse2.Add(t, a);
                    t = Sse2.Add(t, schedule[idx]);
                    f = Sse2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    f = LeftRotate(f, shiftConstants[i]);
                    b = Sse2.Add(b, f);

                    i += 1;
                }

                while (i < 48)
                {
                    int idx = (3 * i + 5) & 15;

                    f = Sse2.Xor(b, c);
                    f = Sse2.Xor(f, d);

                    if (Avx2.IsSupported)
                    {
                        t = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        t = Vector128.Create(tableK[i]);
                    }
                    t = Sse2.Add(t, a);
                    t = Sse2.Add(t, schedule[idx]);
                    f = Sse2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    f = LeftRotate(f, shiftConstants[i]);
                    b = Sse2.Add(b, f);

                    i += 1;
                }

                while (i < 64)
                {
                    int idx = (7 * i) & 15;

                    f = Sse2.Xor(d, Vector128<uint>.AllBitsSet); //Bitwise NOT vector equivilant
                    f = Sse2.Or(f, b);
                    f = Sse2.Xor(f, c);

                    if (Avx2.IsSupported)
                    {
                        t = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        t = Vector128.Create(tableK[i]);
                    }
                    t = Sse2.Add(t, a);
                    t = Sse2.Add(t, schedule[idx]);
                    f = Sse2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    f = LeftRotate(f, shiftConstants[i]);
                    b = Sse2.Add(b, f);

                    i += 1;
                }
            }

            state[0] = Sse2.Add(a, state[0]);
            state[1] = Sse2.Add(b, state[1]);
            state[2] = Sse2.Add(c, state[2]);
            state[3] = Sse2.Add(d, state[3]);
        }

        private static unsafe void ProcessBlocksParallelMD5(Vector256<uint>* state, Vector256<uint>* schedule)
        {
            Vector256<uint> a, b, c, d;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];

            fixed (uint* tableK = MD5TableK)
            fixed (int* shiftConstants = MD5ShiftConsts)
            {
                int i = 0;
                Vector256<int> g;
                Vector256<uint> f, h, t;

                while (i < 16)
                {
                    int idx = i;
                    //f = (b & c) | (~b & d);
                    f = Avx2.AndNot(b, d);
                    f = Avx2.Or(f, Avx2.And(b, c));

                    //f += a + MD5TableK[i] + schedule[g];
                    t = Avx2.BroadcastScalarToVector256(tableK + i);
                    t = Avx2.Add(t, a);
                    t = Avx2.Add(t, schedule[idx]);
                    f = Avx2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    var vtmp = LeftRotate(f, shiftConstants[i]);
                    b = Avx2.Add(b, vtmp);

                    i += 1;
                }

                while (i < 32)
                {
                    int idx = (5 * i + 1) & 15;

                    f = Avx2.And(d, b);
                    f = Avx2.Or(f, Avx2.AndNot(d, c));

                    t = Avx2.BroadcastScalarToVector256(tableK + i);
                    t = Avx2.Add(t, a);
                    t = Avx2.Add(t, schedule[idx]);
                    f = Avx2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    f = LeftRotate(f, shiftConstants[i]);
                    b = Avx2.Add(b, f);

                    i += 1;
                }

                while (i < 48)
                {
                    int idx = (3 * i + 5) & 15;

                    f = Avx2.Xor(b, c);
                    f = Avx2.Xor(f, d);

                    t = Avx2.BroadcastScalarToVector256(tableK + i);
                    t = Avx2.Add(t, a);
                    t = Avx2.Add(t, schedule[idx]);
                    f = Avx2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    f = LeftRotate(f, shiftConstants[i]);
                    b = Avx2.Add(b, f);

                    i += 1;
                }

                while (i < 64)
                {
                    int idx = (7 * i) & 15;

                    f = Avx2.Xor(d, Vector256<uint>.AllBitsSet); //Bitwise NOT vector equivilant
                    f = Avx2.Or(f, b);
                    f = Avx2.Xor(f, c);

                    t = Avx2.BroadcastScalarToVector256(tableK + i);
                    t = Avx2.Add(t, a);
                    t = Avx2.Add(t, schedule[idx]);
                    f = Avx2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    f = LeftRotate(f, shiftConstants[i]);
                    b = Avx2.Add(b, f);

                    i += 1;
                }
            }

            state[0] = Avx2.Add(a, state[0]);
            state[1] = Avx2.Add(b, state[1]);
            state[2] = Avx2.Add(c, state[2]);
            state[3] = Avx2.Add(d, state[3]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe Vector128<uint> LeftRotate(Vector128<uint> vec, int count)
        {
            Vector128<uint> tmp, tmp2;

            tmp = Vector128.CreateScalar(count).AsUInt32();
            tmp2 = Vector128.CreateScalar(32 - count).AsUInt32();

            tmp = Sse2.ShiftLeftLogical(vec, tmp);
            tmp2 = Sse2.ShiftRightLogical(vec, tmp2);
            return Sse2.Or(tmp, tmp2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe Vector256<uint> LeftRotate(Vector256<uint> vec, int count)
        {
            Vector128<uint> tmp, tmp2;

            tmp = Vector128.CreateScalar(count).AsUInt32();
            tmp2 = Vector128.CreateScalar(32 - count).AsUInt32();

            return Avx2.Or(Avx2.ShiftLeftLogical(vec, tmp), Avx2.ShiftRightLogical(vec, tmp2));
        }

        private static unsafe void TransformParallelSchedule(Vector128<uint>* transformed, uint* schedule)
        {
            for (int i = 0; i < 16; ++i)
            {
                if (Avx2.IsSupported)
                {
                    var idx = Vector128.Create(i);
                    idx = Sse2.Add(idx, Vector128.Create(0, 16, 16 * 2, 16 * 3));
                    transformed[i] = Avx2.GatherVector128(schedule, idx, 4);
                }
                else
                {
                    transformed[i] = Vector128.Create(schedule[i], schedule[16 + i], schedule[16 * 2 + i], schedule[16 * 3 + i]);
                }
            }
        }

        private static unsafe void TransformParallelSchedule(Vector256<uint>* transformed, uint* schedule)
        {
            for (int i = 0; i < 16; ++i)
            {
                var idx = Vector256.Create(i);
                idx = Avx2.Add(idx, Vector256.Create(0, 16, 16 * 2, 16 * 3, 16 * 4, 16 * 5, 16 * 6, 16 * 7));
                transformed[i] = Avx2.GatherVector256(schedule, idx, 4);
            }
        }

        private static void ExtractHashState_MD5(Vector128<uint>* state, uint* hash, int hashIdx)
        {
            ExtractHashState(state, hash, hashIdx, 4);
        }

        private static void ExtractHashState_MD5(Vector256<uint>* state, uint* hash, int hashIdx)
        {
            ExtractHashState(state, hash, hashIdx, 4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void StateCopyReversed_MD5(uint* state, byte* hash)
        {
            //x86 is not a platform that supports big endian, so logically x86 intrinsics would not help this.

            uint* uintHash = (uint*)hash;

            uintHash[0] = BinaryPrimitives.ReverseEndianness(state[0]);
            uintHash[1] = BinaryPrimitives.ReverseEndianness(state[1]);
            uintHash[2] = BinaryPrimitives.ReverseEndianness(state[2]);
            uintHash[3] = BinaryPrimitives.ReverseEndianness(state[3]);
        }
    }
}
