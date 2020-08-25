using System;
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
        public static byte[] MD5(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            Span<uint> state = stackalloc uint[4]
            {
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476
            };

            Span<uint> schedule = stackalloc uint[16];

            do
            {
                ctx.PrepareBlock(MemoryMarshal.AsBytes(schedule));

                if (!BitConverter.IsLittleEndian)
                {
                    ReverseEndianess(schedule);
                }

                ProcessBlockMD5(state, schedule);
            }
            while (!ctx.Complete);

            if (!BitConverter.IsLittleEndian)
            {
                ReverseEndianess(state);
            }

            return MemoryMarshal.AsBytes(state).ToArray();
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
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

            Span<bool> flags = stackalloc bool[Vector128<uint>.Count];

            Span<uint> blocks = stackalloc uint[16 * Vector128<uint>.Count];
            Span<Vector128<uint>> schedule = stackalloc Vector128<uint>[16];

            int concurrentHashes = 4;

            do
            {
                for (int i = 0; i < Vector128<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (ctx.Complete)
                        continue;

                    Span<byte> span = MemoryMarshal.AsBytes(blocks.Slice(i * 16, 16));
                    ctx.PrepareBlock(span);
                }

                TransformParallelSchedule(schedule, blocks);

                ProcessBlocksParallelMD5(state, schedule);

                for (int i = 0; i < Vector128<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);

                        ExtractHashFromState(state, hash, i);

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 2);

            if (concurrentHashes > 0)
            {
                Span<uint> singleSchedule = blocks.Slice(0, 16);
                Span<byte> dataBlock = MemoryMarshal.AsBytes(singleSchedule);

                for (int i = 0; i < Vector128<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (ctx.Complete)
                        continue;

                    Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);

                    ExtractHashFromState(state, hash, i);

                    do
                    {
                        ctx.PrepareBlock(dataBlock);

                        ProcessBlockMD5(hash, singleSchedule);
                    }
                    while (!ctx.Complete);
                }
            }

            return hashes;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
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

            Span<bool> flags = stackalloc bool[Vector256<uint>.Count];

            Span<uint> blocks = stackalloc uint[16 * Vector256<uint>.Count];
            Span<Vector256<uint>> schedule = stackalloc Vector256<uint>[16];

            int concurrentHashes = 4;

            do
            {
                for (int i = 0; i < Vector256<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (ctx.Complete)
                        continue;

                    Span<byte> span = MemoryMarshal.AsBytes(blocks.Slice(i * 16, 16));
                    ctx.PrepareBlock(span);
                }

                TransformParallelSchedule(schedule, blocks);

                ProcessBlocksParallelMD5(state, schedule);

                for (int i = 0; i < Vector256<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);

                        ExtractHashFromState(state, hash, i);

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 2);

            if (concurrentHashes > 0)
            {
                Span<uint> singleSchedule = blocks.Slice(0, 16);
                Span<byte> dataBlock = MemoryMarshal.AsBytes(singleSchedule);

                for (int i = 0; i < Vector256<uint>.Count; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (ctx.Complete)
                        continue;

                    Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);

                    ExtractHashFromState(state, hash, i);

                    do
                    {
                        ctx.PrepareBlock(dataBlock);

                        ProcessBlockMD5(hash, singleSchedule);
                    }
                    while (!ctx.Complete);
                }
            }

            return hashes;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static void ProcessBlockMD5(Span<uint> state, Span<uint> schedule)
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void ProcessBlocksParallelMD5(Vector128<uint>* state, Span<Vector128<uint>> schedule)
        {
            Vector128<uint> a, b, c, d;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];

            fixed (Vector128<uint>* schedulePtr = schedule)
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
                    t = Sse2.Add(t, schedulePtr[idx]);
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
                    t = Sse2.Add(t, schedulePtr[idx]);
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
                    t = Sse2.Add(t, schedulePtr[idx]);
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

                    f = Sse2.Xor(d, AllBitsSet_128); //Bitwise NOT vector equivilant
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
                    t = Sse2.Add(t, schedulePtr[idx]);
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void ProcessBlocksParallelMD5(Vector256<uint>* state, Span<Vector256<uint>> schedule)
        {
            Vector256<uint> a, b, c, d;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];

            fixed (Vector256<uint>* schedulePtr = schedule)
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
                    t = Avx2.Add(t, schedulePtr[idx]);
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
                    t = Avx2.Add(t, schedulePtr[idx]);
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
                    t = Avx2.Add(t, schedulePtr[idx]);
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

                    f = Avx2.Xor(d, AllBitsSet_256); //Bitwise NOT vector equivilant
                    f = Avx2.Or(f, b);
                    f = Avx2.Xor(f, c);

                    t = Avx2.BroadcastScalarToVector256(tableK + i);
                    t = Avx2.Add(t, a);
                    t = Avx2.Add(t, schedulePtr[idx]);
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void TransformParallelSchedule(Span<Vector128<uint>> transformed, Span<uint> schedule)
        {
            if (transformed.Length < 16 || schedule.Length < 16 * 4)
                throw new ArgumentException();

            fixed (Vector128<uint>* resptr = transformed)
            fixed (uint* schedPtr = schedule)
            {
                for (int i = 0; i < 16; ++i)
                {
                    if (Avx2.IsSupported)
                    {
                        var idx = Vector128.Create(i);
                        idx = Sse2.Add(idx, GatherIndex_32_128);
                        resptr[i] = Avx2.GatherVector128(schedPtr, idx, 4);
                    }
                    else
                    {
                        resptr[i] = Vector128.Create(schedPtr[i], schedPtr[16 + i], schedPtr[16 * 2 + i], schedPtr[16 * 3 + i]);
                    }
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void TransformParallelSchedule(Span<Vector256<uint>> transformed, Span<uint> schedule)
        {
            if (transformed.Length < 16 || schedule.Length < 16 * 4)
                throw new ArgumentException();

            fixed (Vector256<uint>* resptr = transformed)
            fixed (uint* schedPtr = schedule)
            {
                for (int i = 0; i < 16; ++i)
                {
                    var idx = Vector256.Create(i);
                    idx = Avx2.Add(idx, GatherIndex_32_256);
                    resptr[i] = Avx2.GatherVector256(schedPtr, idx, 4);
                }
            }
        }
    }
}
