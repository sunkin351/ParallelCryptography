﻿using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography
{
    public static partial class HashFunctions
    {
        public static byte[] MD5(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            byte[] hash = new byte[sizeof(uint) * 4];

            Span<uint> state = MemoryMarshal.Cast<byte, uint>(hash);
            state[0] = 0x67452301;
            state[1] = 0xefcdab89;
            state[2] = 0x98badcfe;
            state[3] = 0x10325476;

            var scheduleMemory = MemoryPool.Rent(16);

            Span<uint> schedule = scheduleMemory.Memory.Span;

            do
            {
                ctx.PrepareBlock(MemoryMarshal.Cast<uint, byte>(schedule));

                if (!BitConverter.IsLittleEndian)
                {
                    ReverseEndianess(schedule);
                }

                ProcessBlockMD5(state, schedule);
            }
            while (!ctx.Complete);

            scheduleMemory.Dispose();

            if (!BitConverter.IsLittleEndian)
            {
                ReverseEndianess(state);
            }

            return hash;
        }

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

            SHADataContext[] ctxArr = new SHADataContext[4];
            ctxArr[0] = new SHADataContext(data1);
            ctxArr[1] = new SHADataContext(data2);
            ctxArr[2] = new SHADataContext(data3);
            ctxArr[3] = new SHADataContext(data4);

            byte[][] hashes = AllocateHashs(4, HashSize);

            Span<Vector128<uint>> state = stackalloc Vector128<uint>[4];
            Span<bool> flags = stackalloc bool[4];

            state[0] = Vector128.Create(0x67452301u);
            state[1] = Vector128.Create(0xefcdab89u);
            state[2] = Vector128.Create(0x98badcfeu);
            state[3] = Vector128.Create(0x10325476u);

            var scheduleMemory = MemoryPool.Rent(16 * 4);
            Span<uint> schedule = scheduleMemory.Memory.Span;

            int concurrentHashes = 4;

            do
            {
                for (int i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref ctxArr[i];

                    if (ctx.Complete)
                        continue;

                    Span<byte> span = MemoryMarshal.AsBytes(schedule.Slice(i * 16, 16));
                    ctx.PrepareBlock(span);
                }

                ProcessBlocksParallelMD5(state, schedule);

                for (int i = 0; i < 4; ++i)
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

            if (concurrentHashes == 0)
            {
                return hashes;
            }

            Span<uint> singleSchedule = schedule.Slice(0, 16);

            for (int i = 0; i < 4; ++i)
            {
                ref SHADataContext ctx = ref ctxArr[i];

                if (ctx.Complete)
                    continue;

                Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);
                Span<byte> asDataBlock = MemoryMarshal.AsBytes(singleSchedule);

                ExtractHashFromState(state, hash, i);

                do
                {
                    ctx.PrepareBlock(asDataBlock);

                    ProcessBlockMD5(hash, singleSchedule);
                }
                while (!ctx.Complete);
            }

            scheduleMemory.Dispose();

            return hashes;
        }

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

        private static unsafe void ProcessBlocksParallelMD5(Span<Vector128<uint>> state, Span<uint> schedule)
        {
            Vector128<uint> a, b, c, d;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];

            fixed (uint* schedulePtr = schedule)
            fixed (uint* tableK = MD5TableK)
            fixed (int* shiftConstants = MD5ShiftConsts)
            {
                int i = 0;
                Vector128<int> g;
                Vector128<uint> f, h, t;

                //while (i < 16)
                //{
                //    f = (b & c) | (~b & d);
                //    g = i;

                //    f += a + MD5TableK[i] + schedule[g];
                //    a = d;
                //    d = c;
                //    c = b;
                //    b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                //    i += 1;
                //}

                while (i < 16)
                {
                    int idx = i;
                    //f = (b & c) | (~b & d);
                    f = Sse2.AndNot(b, d);
                    f = Sse2.Or(f, Sse2.And(b, c));

                    //f += a + MD5TableK[i] + schedule[g];
                    if (Avx2.IsSupported)
                    {
                        g = Vector128.Create(idx);
                        g = Sse2.Add(g, MD5GatherIndex);
                        h = Avx2.GatherVector128(schedulePtr, g, 4);
                        t = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        t = Vector128.Create(tableK[i]);
                        h = Vector128.Create(schedulePtr[idx], schedulePtr[16 + idx], schedulePtr[16 * 2 + idx], schedulePtr[16 * 3 + idx]);
                    }
                    t = Sse2.Add(t, a);
                    t = Sse2.Add(t, h);
                    f = Sse2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    var vtmp = LeftRotate(f, shiftConstants[i]);
                    b = Sse2.Add(b, vtmp);

                    i += 1;
                }

                //while (i < 32)
                //{
                //    f = (d & b) | (~d & c);
                //    g = (5 * i + 1) & 15;

                //    f += a + MD5TableK[i] + schedule[g];
                //    a = d;
                //    d = c;
                //    c = b;
                //    b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                //    i += 1;
                //}

                while (i < 32)
                {
                    int idx = (5 * i + 1) & 15;

                    f = Sse2.And(d, b);
                    f = Sse2.Or(f, Sse2.AndNot(d, c));

                    if (Avx2.IsSupported)
                    {
                        g = Vector128.Create(idx);
                        g = Sse2.Add(g, MD5GatherIndex);
                        h = Avx2.GatherVector128(schedulePtr, g, 4);
                        t = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        t = Vector128.Create(tableK[i]);
                        h = Vector128.Create(schedulePtr[idx], schedulePtr[16 + idx], schedulePtr[16 * 2 + idx], schedulePtr[16 * 3 + idx]);
                    }
                    t = Sse2.Add(t, a);
                    t = Sse2.Add(t, h);
                    f = Sse2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    f = LeftRotate(f, shiftConstants[i]);
                    b = Sse2.Add(b, f);

                    i += 1;
                }

                //while (i < 48)
                //{
                //    f = b ^ c ^ d;
                //    g = (3 * i + 5) & 15;

                //    f += a + MD5TableK[i] + schedule[g];
                //    a = d;
                //    d = c;
                //    c = b;
                //    b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                //    i += 1;
                //}

                while (i < 48)
                {
                    int idx = (3 * i + 5) & 15;

                    f = Sse2.Xor(b, c);
                    f = Sse2.Xor(f, d);

                    if (Avx2.IsSupported)
                    {
                        g = Vector128.Create(idx);
                        g = Sse2.Add(g, MD5GatherIndex);
                        h = Avx2.GatherVector128(schedulePtr, g, 4);
                        t = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        t = Vector128.Create(tableK[i]);
                        h = Vector128.Create(schedulePtr[idx], schedulePtr[16 + idx], schedulePtr[16 * 2 + idx], schedulePtr[16 * 3 + idx]);
                    }
                    t = Sse2.Add(t, a);
                    t = Sse2.Add(t, h);
                    f = Sse2.Add(f, t);

                    a = d;
                    d = c;
                    c = b;

                    f = LeftRotate(f, shiftConstants[i]);
                    b = Sse2.Add(b, f);

                    i += 1;
                }

                //while (i < 64)
                //{
                //    f = c ^ (b | ~d);
                //    g = (7 * i) & 15;

                //    f += a + MD5TableK[i] + schedule[g];
                //    a = d;
                //    d = c;
                //    c = b;
                //    b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                //    i += 1;
                //}

                while (i < 64)
                {
                    int idx = (7 * i) & 15;

                    f = Sse2.Xor(d, AllBitsSet); //Bitwise NOT vector equivilant
                    f = Sse2.Or(f, b);
                    f = Sse2.Xor(f, c);

                    if (Avx2.IsSupported)
                    {
                        g = Vector128.Create(idx);
                        g = Sse2.Add(g, MD5GatherIndex);
                        h = Avx2.GatherVector128(schedulePtr, g, 4);
                        t = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        t = Vector128.Create(tableK[i]);
                        h = Vector128.Create(schedulePtr[idx], schedulePtr[16 + idx], schedulePtr[16 * 2 + idx], schedulePtr[16 * 3 + idx]);
                    }
                    t = Sse2.Add(t, a);
                    t = Sse2.Add(t, h);
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
    }
}
