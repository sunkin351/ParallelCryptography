using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Numerics;

namespace ParallelCryptography
{
    public static partial class HashFunctions
    {
        

        public static byte[] MD5(byte[] data)
        {
            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException("Big Endian computing not supported by this MD5 implementation");
            }

            SHADataContext ctx = new SHADataContext(data);

            byte[] hash = new byte[sizeof(uint) * 4];

            Span<uint> state = MemoryMarshal.Cast<byte, uint>(hash);
            state[0] = 0x67452301;
            state[1] = 0xefcdab89;
            state[2] = 0x98badcfe;
            state[3] = 0x10325476;

            uint[] scheduleMemory = PooledMemory.Rent(16);

            Span<uint> schedule = scheduleMemory.AsSpan(0, 16);

            do
            {
                ctx.PrepareBlock(MemoryMarshal.Cast<uint, byte>(schedule));

                ProcessBlockMD5(state, schedule);
            }
            while (!ctx.Complete);

            return hash;
        }

        public static unsafe byte[][] MD5Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException("SSE2 instructions not available");
            }

            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException("Big Endian computing not supported by this MD5 implementation");
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

            uint[] scheduleMemory = PooledMemory.Rent(16 * 4);
            Span<uint> schedule = scheduleMemory.AsSpan(0, 16 * 4);

            int concurrentHashes;

            do
            {
                concurrentHashes = 0;

                for (int i = 0; i < 4; ++i)
                {
                    Span<byte> span = MemoryMarshal.Cast<uint, byte>(schedule.Slice(i * 16, 16));
                    ctxArr[i].PrepareBlock(span);
                    concurrentHashes += ctxArr[i].Complete ? 0 : 1;
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
                    }
                }
            }
            while (concurrentHashes > 2);

            Span<uint> singleSchedule = schedule.Slice(0, 16);

            for (int i = 0; i < 4; ++i)
            {
                ref SHADataContext ctx = ref ctxArr[i];

                if (ctx.Complete)
                    continue;

                Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);
                Span<byte> asDataBlock = MemoryMarshal.Cast<uint, byte>(singleSchedule);

                ExtractHashFromState(state, hash, i);

                do
                {
                    ctx.PrepareBlock(asDataBlock);

                    ProcessBlockMD5(hash, singleSchedule);
                }
                while (!ctx.Complete);
            }

            PooledMemory.Return(scheduleMemory);

            return hashes;
        }

        private static void ProcessBlockMD5(Span<uint> state, Span<uint> schedule)
        {
            int i = 0;
            uint a, b, c, d;
            uint f;
            int g;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];

            while (i < 16)
            {
                f = (b & c) | (~b & d);
                g = i;

                f += a + MD5TableK[i] + schedule[g];
                a = d;
                d = c;
                c = b;
                b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                i += 1;
            }

            while (i < 32)
            {
                f = (d & b) | (~d & c);
                g = (5 * i + 1) & 15;

                f += a + MD5TableK[i] + schedule[g];
                a = d;
                d = c;
                c = b;
                b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                i += 1;
            }

            while (i < 48)
            {
                f = b ^ c ^ d;
                g = (3 * i + 5) & 15;

                f += a + MD5TableK[i] + schedule[g];
                a = d;
                d = c;
                c = b;
                b += BitOperations.RotateLeft(f, MD5ShiftConsts[i]);

                i += 1;
            }

            while (i < 64)
            {
                f = c ^ (b | ~d);
                g = (7 * i) & 15;

                f += a + MD5TableK[i] + schedule[g];
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
            {
                int i = 0;
                Vector128<int> g, b32 = Vector128.Create(32);
                Vector128<uint> f, h;

                while (i < 16)
                {
                    f = Sse2.AndNot(b, d);
                    f = Sse2.Or(f, Sse2.And(b, c));

                    f = Sse2.Add(f, a);
                    f = Sse2.Add(f, Vector128.Create(MD5TableK[i]));

                    if (Avx2.IsSupported)
                    {
                        g = Sse2.Add(Vector128.Create(i), MD5GatherIndex);
                        h = Avx2.GatherVector128(schedulePtr, g, 4);
                    }
                    else
                    {
                        h = Vector128.Create(schedulePtr[i], schedulePtr[16 + i], schedulePtr[16 * 2 + i], schedulePtr[16 * 3 + i]);
                    }
                    f = Sse2.Add(f, h);

                    g = Vector128.Create(MD5ShiftConsts[i]);
                    h = Sse2.ShiftLeftLogical(f, g.AsUInt32());
                    g = Sse2.Subtract(b32, g);
                    f = Sse2.ShiftRightLogical(f, g.AsUInt32());
                    a = d;
                    d = c;
                    c = b;
                    f = Sse2.Or(f, h);
                    b = Sse2.Add(b, f);

                    i += 1;
                }

                while (i < 32)
                {
                    f = Sse2.Xor(b, c);
                    f = Sse2.Xor(f, d);

                    f = Sse2.Add(f, a);
                    f = Sse2.Add(f, Vector128.Create(MD5TableK[i]));

                    int idx = (5 * i + 1) & 15;

                    if (Avx2.IsSupported)
                    {
                        g = Sse2.Add(Vector128.Create(idx), MD5GatherIndex);
                        h = Avx2.GatherVector128(schedulePtr, g, 4);
                    }
                    else
                    {
                        h = Vector128.Create(schedulePtr[idx], schedulePtr[16 + idx], schedulePtr[16 * 2 + idx], schedulePtr[16 * 3 + idx]);
                    }
                    f = Sse2.Add(f, h);

                    g = Vector128.Create(MD5ShiftConsts[i]);
                    h = Sse2.ShiftLeftLogical(f, g.AsUInt32());
                    g = Sse2.Subtract(b32, g);
                    f = Sse2.ShiftRightLogical(f, g.AsUInt32());
                    a = d;
                    d = c;
                    c = b;
                    f = Sse2.Or(f, h);
                    b = Sse2.Add(b, f);

                    i += 1;
                }

                while (i < 48)
                {
                    f = Sse2.AndNot(d, c);
                    f = Sse2.Or(f, Sse2.And(b, d));

                    f = Sse2.Add(f, a);
                    f = Sse2.Add(f, Vector128.Create(MD5TableK[i]));

                    int idx = (3 * i + 5) & 15;

                    if (Avx2.IsSupported)
                    {
                        g = Sse2.Add(Vector128.Create(idx), MD5GatherIndex);
                        h = Avx2.GatherVector128(schedulePtr, g, 4);
                    }
                    else
                    {
                        h = Vector128.Create(schedulePtr[idx], schedulePtr[16 + idx], schedulePtr[16 * 2 + idx], schedulePtr[16 * 3 + idx]);
                    }
                    f = Sse2.Add(f, h);

                    g = Vector128.Create(MD5ShiftConsts[i]);
                    h = Sse2.ShiftLeftLogical(f, g.AsUInt32());
                    g = Sse2.Subtract(b32, g);
                    f = Sse2.ShiftRightLogical(f, g.AsUInt32());
                    a = d;
                    d = c;
                    c = b;
                    f = Sse2.Or(f, h);
                    b = Sse2.Add(b, f);

                    i += 1;
                }

                while (i < 64)
                {
                    f = Sse2.Xor(d, AllBitsSet); //Bitwise NOT
                    f = Sse2.Or(f, b);
                    f = Sse2.Xor(f, c);

                    f = Sse2.Add(f, a);
                    f = Sse2.Add(f, Vector128.Create(MD5TableK[i]));

                    int idx = (7 * i) & 15;

                    if (Avx2.IsSupported)
                    {
                        g = Sse2.Add(Vector128.Create(idx), MD5GatherIndex);
                        h = Avx2.GatherVector128(schedulePtr, g, 4);
                    }
                    else
                    {
                        h = Vector128.Create(schedulePtr[idx], schedulePtr[16 + idx], schedulePtr[16 * 2 + idx], schedulePtr[16 * 3 + idx]);
                    }
                    f = Sse2.Add(f, h);

                    g = Vector128.Create(MD5ShiftConsts[i]);
                    h = Sse2.ShiftLeftLogical(f, g.AsUInt32());
                    g = Sse2.Subtract(b32, g);
                    f = Sse2.ShiftRightLogical(f, g.AsUInt32());
                    a = d;
                    d = c;
                    c = b;
                    f = Sse2.Or(f, h);
                    b = Sse2.Add(b, f);

                    i += 1;
                }

                state[0] = Sse2.Add(a, state[0]);
                state[1] = Sse2.Add(b, state[1]);
                state[2] = Sse2.Add(c, state[2]);
                state[3] = Sse2.Add(d, state[3]);
            }
        }
    }
}
