using System;
using System.Buffers;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography
{
    public static partial class HashFunctions
    {


        public static byte[] Sha512(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            Span<ulong> state = stackalloc ulong[8] 
            {
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179
            };

            var scheduleMemory = MemoryPool<ulong>.Shared.Rent(80);
            Span<ulong> schedule = scheduleMemory.Memory.Span;

            Span<byte> dataPortion = MemoryMarshal.AsBytes(schedule.Slice(0, 16));

            do
            {
                ctx.PrepareBlock(dataPortion);
                InitScheduleSHA512(schedule);
                ProcessBlockSHA512(state, schedule);
            }
            while (!ctx.Complete);

            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(state);
            }

            return MemoryMarshal.AsBytes(state).ToArray();
        }

        public static byte[][] Sha512Parallel(byte[] data1, byte[] data2)
        {
            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException("SSE2 instructions not available");
            }

            Span<Vector128<ulong>> state = stackalloc Vector128<ulong>[8] 
            {
                Vector128.Create(0x6a09e667f3bcc908u),
                Vector128.Create(0xbb67ae8584caa73bu),
                Vector128.Create(0x3c6ef372fe94f82bu),
                Vector128.Create(0xa54ff53a5f1d36f1u),
                Vector128.Create(0x510e527fade682d1u),
                Vector128.Create(0x9b05688c2b3e6c1fu),
                Vector128.Create(0x1f83d9abfb41bd6bu),
                Vector128.Create(0x5be0cd19137e2179u),
            };

            Span<bool> flags = stackalloc bool[2];
            SHADataContext[] contexts = new SHADataContext[2];

            contexts[0] = new SHADataContext(data1);
            contexts[1] = new SHADataContext(data2);

            var scheduleMemory = MemoryPool<ulong>.Shared.Rent(80 * 2);
            Span<ulong> schedule = scheduleMemory.Memory.Span;

            byte[][] hashes = AllocateHashs(2, sizeof(ulong) * 8);

            int concurrentHashes, i;

            do
            {
                concurrentHashes = 0;

                for (i = 0; i < 2; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock(MemoryMarshal.AsBytes(schedule.Slice(i * 80, 16)));
                        concurrentHashes += ctx.Complete ? 0 : 1;

                        InitScheduleSHA512(schedule.Slice(i * 80, 80));
                    }
                }

                ProcessBlocksParallelSHA512(state, schedule);

                for (i = 0; i < 2; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        Span<ulong> hash = MemoryMarshal.Cast<byte, ulong>(hashes[i]);

                        ExtractHashFromState(state, hash, i);
                    }
                }
            }
            while (concurrentHashes == 2);

            Span<ulong> block = schedule.Slice(0, 80);

            for (i = 0; i < 2; ++i)
            {
                ref SHADataContext ctx = ref contexts[i];

                if (ctx.Complete)
                {
                    continue;
                }

                Span<ulong> hash = MemoryMarshal.Cast<byte, ulong>(hashes[i]);

                ExtractHashFromState(state, hash, i);

                var dataBlock = MemoryMarshal.AsBytes(block.Slice(0, 16));

                do
                {
                    ctx.PrepareBlock(dataBlock);

                    InitScheduleSHA512(block);

                    ProcessBlockSHA512(hash, block);

                } while (!ctx.Complete);
            }

            scheduleMemory.Dispose();

            if (BitConverter.IsLittleEndian)
            {
                foreach (var hash in hashes)
                {
                    Span<ulong> hashSpan = MemoryMarshal.Cast<byte, ulong>(hash);
                    ReverseEndianess(hashSpan);
                }
            }

            return hashes;
        }

        public static byte[][] Sha512Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!Avx2.IsSupported)
            {
                throw new NotSupportedException("SSE2 instructions not available");
            }

            Span<Vector256<ulong>> state = stackalloc Vector256<ulong>[8]
            {
                Vector256.Create(0x6a09e667f3bcc908u),
                Vector256.Create(0xbb67ae8584caa73bu),
                Vector256.Create(0x3c6ef372fe94f82bu),
                Vector256.Create(0xa54ff53a5f1d36f1u),
                Vector256.Create(0x510e527fade682d1u),
                Vector256.Create(0x9b05688c2b3e6c1fu),
                Vector256.Create(0x1f83d9abfb41bd6bu),
                Vector256.Create(0x5be0cd19137e2179u),
            };

            Span<bool> flags = stackalloc bool[4];
            SHADataContext[] contexts = new SHADataContext[4];

            contexts[0] = new SHADataContext(data1);
            contexts[1] = new SHADataContext(data2);
            contexts[2] = new SHADataContext(data3);
            contexts[3] = new SHADataContext(data4);

            var scheduleMemory = MemoryPool<ulong>.Shared.Rent(80 * 4);
            Span<ulong> schedule = scheduleMemory.Memory.Span;

            byte[][] hashes = AllocateHashs(4, sizeof(ulong) * 8);

            int concurrentHashes, i;

            do
            {
                concurrentHashes = 0;

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock(MemoryMarshal.AsBytes(schedule.Slice(i * 80, 16)));
                        concurrentHashes += ctx.Complete ? 0 : 1;

                        InitScheduleSHA512(schedule.Slice(i * 80, 80));
                    }
                }

                ProcessBlocksParallelSHA512(state, schedule);

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        Span<ulong> hash = MemoryMarshal.Cast<byte, ulong>(hashes[i]);

                        ExtractHashFromState(state, hash, i);
                    }
                }
            }
            while (concurrentHashes > 2);

            Span<ulong> block = schedule.Slice(0, 80);

            for (i = 0; i < 4; ++i)
            {
                ref SHADataContext ctx = ref contexts[i];

                if (ctx.Complete)
                {
                    continue;
                }

                Span<ulong> hash = MemoryMarshal.Cast<byte, ulong>(hashes[i]);

                ExtractHashFromState(state, hash, i);

                var dataBlock = MemoryMarshal.AsBytes(block.Slice(0, 16));

                do
                {
                    ctx.PrepareBlock(dataBlock);

                    InitScheduleSHA512(block);

                    ProcessBlockSHA512(hash, block);

                } while (!ctx.Complete);
            }

            scheduleMemory.Dispose();

            if (BitConverter.IsLittleEndian)
            {
                foreach (var hash in hashes)
                {
                    Span<ulong> hashSpan = MemoryMarshal.Cast<byte, ulong>(hash);
                    ReverseEndianess(hashSpan);
                }
            }

            return hashes;
        }

        private static void ProcessBlockSHA512(Span<ulong> state, Span<ulong> schedule)
        {
            ulong a, b, c, d, e, f, g, h;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];
            f = state[5];
            g = state[6];
            h = state[7];

            for (int i = 0; i < 80; ++i)
            {
                var ch = (e & f) ^ (~e & g);
                var maj = (a & b) ^ (a & c) ^ (b & c);
                var S0 = BitOperations.RotateRight(a, 28) ^ BitOperations.RotateRight(a, 34) ^ BitOperations.RotateRight(a, 39);
                var S1 = BitOperations.RotateRight(e, 14) ^ BitOperations.RotateRight(e, 18) ^ BitOperations.RotateRight(e, 41);
                var tmp1 = h + S1 + ch + SHA512TableK[i] + schedule[i];
                var tmp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + tmp1;
                d = c;
                c = b;
                b = a;
                a = tmp1 + tmp2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

        private static unsafe void ProcessBlocksParallelSHA512(Span<Vector128<ulong>> state, Span<ulong> schedule)
        {
            Vector128<ulong> a, b, c, d, e, f, g, h;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];
            f = state[5];
            g = state[6];
            h = state[7];

            fixed (ulong* schedule_ptr = schedule)
            fixed (ulong* tableK = SHA512TableK)
            {
                for (int i = 0; i < 80; ++i)
                {
                    Vector128<ulong> tmp1, tmp2, S, ch;
                    if (Avx2.IsSupported)
                    {
                        var idx = Sse2.Add(Vector128.Create((long)i), Sha512GatherIndex_128);
                        tmp1 = Avx2.GatherVector128(schedule_ptr, idx, 8);
                    }
                    else
                    {
                        tmp1 = Vector128.Create(schedule_ptr[i], schedule_ptr[i + 80]);
                    }

                    //var S0 = BitOperations.RotateRight(a, 28) ^ BitOperations.RotateRight(a, 34) ^ BitOperations.RotateRight(a, 39);
                    S = Sse2.Or(Sse2.ShiftRightLogical(e, 14), Sse2.ShiftLeftLogical(e, 64 - 14));
                    S = Sse2.Xor(S, Sse2.Or(Sse2.ShiftRightLogical(e, 18), Sse2.ShiftLeftLogical(e, 64 - 18)));
                    S = Sse2.Xor(S, Sse2.Or(Sse2.ShiftRightLogical(e, 41), Sse2.ShiftLeftLogical(e, 64 - 41)));

                    tmp1 = Sse2.Add(tmp1, Vector128.Create(tableK[i]));
                    tmp1 = Sse2.Add(tmp1, h);

                    ch = Sse2.And(e, f);
                    ch = Sse2.Xor(ch, Sse2.AndNot(e, g));

                    tmp1 = Sse2.Add(tmp1, S);
                    tmp1 = Sse2.Add(tmp1, ch);

                    S = Sse2.Or(Sse2.ShiftRightLogical(a, 28), Sse2.ShiftLeftLogical(a, 64 - 28));
                    S = Sse2.Xor(S, Sse2.Or(Sse2.ShiftRightLogical(a, 34), Sse2.ShiftLeftLogical(a, 64 - 34)));
                    S = Sse2.Xor(S, Sse2.Or(Sse2.ShiftRightLogical(a, 39), Sse2.ShiftLeftLogical(a, 64 - 39)));

                    tmp2 = Sse2.And(a, b);
                    tmp2 = Sse2.Xor(tmp2, Sse2.And(a, c));
                    tmp2 = Sse2.Xor(tmp2, Sse2.And(b, c));

                    tmp2 = Sse2.Add(tmp2, S);

                    h = g;
                    g = f;
                    f = e;
                    e = Sse2.Add(d, tmp1);
                    d = c;
                    c = b;
                    b = a;
                    a = Sse2.Add(tmp1, tmp2);
                }
            }

            state[0] = Sse2.Add(a, state[0]);
            state[1] = Sse2.Add(b, state[1]);
            state[2] = Sse2.Add(c, state[2]);
            state[3] = Sse2.Add(d, state[3]);
            state[4] = Sse2.Add(e, state[4]);
            state[5] = Sse2.Add(f, state[5]);
            state[6] = Sse2.Add(g, state[6]);
            state[7] = Sse2.Add(h, state[7]);
        }

        private static unsafe void ProcessBlocksParallelSHA512(Span<Vector256<ulong>> state, Span<ulong> schedule)
        {
            Vector256<ulong> a, b, c, d, e, f, g, h;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];
            f = state[5];
            g = state[6];
            h = state[7];

            fixed (ulong* schedule_ptr = schedule)
            fixed (ulong* tableK = SHA512TableK)
            {
                for (int i = 0; i < 80; ++i)
                {
                    Vector256<ulong> tmp1, tmp2, S, ch;

                    {
                        var idx = Avx2.Add(Vector256.Create((long)i), Sha512GatherIndex_256);
                        tmp1 = Avx2.GatherVector256(schedule_ptr, idx, 8);
                    }

                    //var S0 = BitOperations.RotateRight(a, 28) ^ BitOperations.RotateRight(a, 34) ^ BitOperations.RotateRight(a, 39);
                    S = Avx2.Or(Avx2.ShiftRightLogical(e, 14), Avx2.ShiftLeftLogical(e, 64 - 14));
                    S = Avx2.Xor(S, Avx2.Or(Avx2.ShiftRightLogical(e, 18), Avx2.ShiftLeftLogical(e, 64 - 18)));
                    S = Avx2.Xor(S, Avx2.Or(Avx2.ShiftRightLogical(e, 41), Avx2.ShiftLeftLogical(e, 64 - 41)));

                    tmp1 = Avx2.Add(tmp1, Vector256.Create(tableK[i]));
                    tmp1 = Avx2.Add(tmp1, h);

                    ch = Avx2.And(e, f);
                    ch = Avx2.Xor(ch, Avx2.AndNot(e, g));

                    tmp1 = Avx2.Add(tmp1, S);
                    tmp1 = Avx2.Add(tmp1, ch);

                    S = Avx2.Or(Avx2.ShiftRightLogical(a, 28), Avx2.ShiftLeftLogical(a, 64 - 28));
                    S = Avx2.Xor(S, Avx2.Or(Avx2.ShiftRightLogical(a, 34), Avx2.ShiftLeftLogical(a, 64 - 34)));
                    S = Avx2.Xor(S, Avx2.Or(Avx2.ShiftRightLogical(a, 39), Avx2.ShiftLeftLogical(a, 64 - 39)));

                    tmp2 = Avx2.And(a, b);
                    tmp2 = Avx2.Xor(tmp2, Avx2.And(a, c));
                    tmp2 = Avx2.Xor(tmp2, Avx2.And(b, c));

                    tmp2 = Avx2.Add(tmp2, S);

                    h = g;
                    g = f;
                    f = e;
                    e = Avx2.Add(d, tmp1);
                    d = c;
                    c = b;
                    b = a;
                    a = Avx2.Add(tmp1, tmp2);
                }
            }

            state[0] = Avx2.Add(a, state[0]);
            state[1] = Avx2.Add(b, state[1]);
            state[2] = Avx2.Add(c, state[2]);
            state[3] = Avx2.Add(d, state[3]);
            state[4] = Avx2.Add(e, state[4]);
            state[5] = Avx2.Add(f, state[5]);
            state[6] = Avx2.Add(g, state[6]);
            state[7] = Avx2.Add(h, state[7]);
        }

        private static void InitScheduleSHA512(Span<ulong> schedule)
        {
            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(schedule.Slice(0, 16));
            }

            for (int i = 16; i < 80; ++i)
            {
                var tmp = schedule[i - 15];
                var s0 = BitOperations.RotateRight(tmp, 1) ^ BitOperations.RotateRight(tmp, 8) ^ (tmp >> 7);

                tmp = schedule[i - 2];
                var s1 = BitOperations.RotateRight(tmp, 19) ^ BitOperations.RotateRight(tmp, 61) ^ (tmp >> 6);

                schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
            }
        }

    }
}
