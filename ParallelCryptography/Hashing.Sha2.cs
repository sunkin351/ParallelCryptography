using System;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography
{
    public static partial class HashFunctions
    {
        public static byte[] SHA256(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            byte[] hash = new byte[sizeof(uint) * 8];

            Span<uint> state = MemoryMarshal.Cast<byte, uint>(hash);

            state[0] = 0x6a09e667;
            state[1] = 0xbb67ae85;
            state[2] = 0x3c6ef372;
            state[3] = 0xa54ff53a;
            state[4] = 0x510e527f;
            state[5] = 0x9b05688c;
            state[6] = 0x1f83d9ab;
            state[7] = 0x5be0cd19;

            var scheduleMemory = MemoryPool.Rent(64);
            Span<uint> schedule = scheduleMemory.Memory.Span;

            Span<byte> dataPortion = MemoryMarshal.Cast<uint, byte>(schedule.Slice(0, 16));

            Debug.Assert(dataPortion.Length == 64);

            do
            {
                ctx.PrepareBlock(dataPortion);
                InitScheduleSHA256(schedule);
                ProcessBlockSHA256(state, schedule);
            }
            while (!ctx.Complete);

            scheduleMemory.Dispose();

            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(state);
            }

            return hash;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static byte[][] SHA256Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException("SSE2 instructions not available");
            }

            Span<Vector128<uint>> state = stackalloc Vector128<uint>[8];
            Span<bool> flags = stackalloc bool[4];
            SHADataContext[] contexts = new SHADataContext[4];

            contexts[0] = new SHADataContext(data1);
            contexts[1] = new SHADataContext(data2);
            contexts[2] = new SHADataContext(data3);
            contexts[3] = new SHADataContext(data4);

            var scheduleMemory = MemoryPool.Rent(64 * 4);
            Span<uint> schedule = scheduleMemory.Memory.Span;
            byte[][] hashes = AllocateHashs(4, sizeof(uint) * 8);

            state[0] = Vector128.Create(0x6a09e667u);
            state[1] = Vector128.Create(0xbb67ae85u);
            state[2] = Vector128.Create(0x3c6ef372u);
            state[3] = Vector128.Create(0xa54ff53au);
            state[4] = Vector128.Create(0x510e527fu);
            state[5] = Vector128.Create(0x9b05688cu);
            state[6] = Vector128.Create(0x1f83d9abu);
            state[7] = Vector128.Create(0x5be0cd19u);

            int concurrentHashes, i;

            do
            {
                concurrentHashes = 0;

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock(MemoryMarshal.Cast<uint, byte>(schedule.Slice(i * 64, 16)));
                        concurrentHashes += ctx.Complete ? 0 : 1;

                        InitScheduleSHA256(schedule.Slice(i * 64, 64));
                    }
                }

                ProcessBlocksParallelSHA256(state, schedule);

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);

                        ExtractHashFromState(state, hash, i);
                    }
                }
            }
            while (concurrentHashes > 2);

            Span<uint> block = schedule.Slice(0, 64);

            for (i = 0; i < 4; ++i)
            {
                ref SHADataContext ctx = ref contexts[i];

                if (ctx.Complete)
                {
                    continue;
                }

                Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);

                ExtractHashFromState(state, hash, i);

                var dataBlock = MemoryMarshal.Cast<uint, byte>(block.Slice(0, 16));

                do
                {
                    ctx.PrepareBlock(dataBlock);

                    InitScheduleSHA1(block);

                    ProcessBlockSHA1(hash, block);

                } while (!ctx.Complete);
            }

            scheduleMemory.Dispose();

            if (BitConverter.IsLittleEndian)
            {
                foreach (var hash in hashes)
                {
                    Span<uint> hashSpan = MemoryMarshal.Cast<byte, uint>(hash);
                    ReverseEndianess(hashSpan);
                }
            }
            
            return hashes;
        }

        private static void ProcessBlockSHA256(Span<uint> state, Span<uint> schedule)
        {
            uint a, b, c, d, e, f, g, h;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];
            f = state[5];
            g = state[6];
            h = state[7];

            for (int i = 0; i < 64; ++i)
            {
                var ch = (e & f) ^ (~e & g);
                var maj = (a & b) ^ (a & c) ^ (b & c);
                var S1 = BitOperations.RotateRight(e, 6) ^ BitOperations.RotateRight(e, 11) ^ BitOperations.RotateRight(e, 25);
                var S0 = BitOperations.RotateRight(a, 2) ^ BitOperations.RotateRight(a, 13) ^ BitOperations.RotateRight(a, 22);
                var tmp1 = h + S1 + ch + SHA256TableK[i] + schedule[i];
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

        private static unsafe void ProcessBlocksParallelSHA256(Span<Vector128<uint>> state, Span<uint> schedule)
        {
            Vector128<uint> a, b, c, d, e, f, g, h;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];
            f = state[5];
            g = state[6];
            h = state[7];

            fixed (uint* schedule_ptr = schedule)
            {
                for (int i = 0; i < 64; ++i)
                {
                    Vector128<uint> tmp1, tmp2, S, ch;
                    if (Avx2.IsSupported)
                    {
                        var idx = Sse2.Add(Vector128.Create(i), Sha256GatherIndex);
                        tmp1 = Avx2.GatherVector128(schedule_ptr, idx, 4);
                    }
                    else
                    {
                        tmp1 = Vector128.Create(schedule_ptr[i], schedule_ptr[i + 64], schedule_ptr[i + 64 * 2], schedule_ptr[i + 64 * 3]);
                    }

                    //Rotate Right by 6
                    S = Sse2.Or(Sse2.ShiftRightLogical(e, 6), Sse2.ShiftLeftLogical(e, 32 - 6));

                    S = Sse2.Xor(S, Sse2.Or(Sse2.ShiftRightLogical(e, 11), Sse2.ShiftLeftLogical(e, 32 - 11)));

                    S = Sse2.Xor(S, Sse2.Or(Sse2.ShiftRightLogical(e, 25), Sse2.ShiftLeftLogical(e, 32 - 25)));

                    tmp1 = Sse2.Add(tmp1, Vector128.Create(SHA256TableK[i]));
                    tmp1 = Sse2.Add(tmp1, h);

                    ch = Sse2.And(e, f);
                    ch = Sse2.Xor(ch, Sse2.AndNot(e, g));

                    tmp1 = Sse2.Add(tmp1, S);
                    tmp1 = Sse2.Add(tmp1, ch);

                    S = Sse2.Or(Sse2.ShiftRightLogical(a, 2), Sse2.ShiftLeftLogical(a, 32 - 2));
                    S = Sse2.Xor(S, Sse2.Or(Sse2.ShiftRightLogical(a, 13), Sse2.ShiftLeftLogical(a, 32 - 13)));
                    S = Sse2.Xor(S, Sse2.Or(Sse2.ShiftRightLogical(a, 22), Sse2.ShiftLeftLogical(a, 32 - 22)));

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

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void InitScheduleSHA256(Span<uint> chunk)
        {
            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(chunk.Slice(0, 16));
            }

            for (int i = 16; i < 64; ++i)
            {
                var tmp = chunk[i - 15];
                var s0 = BitOperations.RotateRight(tmp, 7) ^ BitOperations.RotateRight(tmp, 18) ^ (tmp >> 3);

                tmp = chunk[i - 2];
                var s1 = BitOperations.RotateRight(tmp, 17) ^ BitOperations.RotateRight(tmp, 19) ^ (tmp >> 10);

                chunk[i] = chunk[i - 16] + s0 + chunk[i - 7] + s1;
            }
        }
    }
}
