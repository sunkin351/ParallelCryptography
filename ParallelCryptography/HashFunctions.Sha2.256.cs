using System;
using System.Buffers.Binary;
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
        public static byte[] SHA256(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            Span<uint> state = stackalloc uint[8]
            {
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19
            };

            Span<uint> schedule = stackalloc uint[64];

            Span<byte> dataPortion = MemoryMarshal.Cast<uint, byte>(schedule.Slice(0, 16));

            do
            {
                ctx.PrepareBlock(dataPortion);
                InitScheduleSHA256(schedule);
                ProcessBlockSHA256(state, schedule);
            }
            while (!ctx.Complete);

            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(state);
            }

            return MemoryMarshal.AsBytes(state).ToArray();
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static byte[][] SHA256Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException(SSE2_NotAvailable);
            }

            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
            }

            Span<Vector128<uint>> state = stackalloc Vector128<uint>[8]
            {
                Vector128.Create(0x6a09e667u),
                Vector128.Create(0xbb67ae85u),
                Vector128.Create(0x3c6ef372u),
                Vector128.Create(0xa54ff53au),
                Vector128.Create(0x510e527fu),
                Vector128.Create(0x9b05688cu),
                Vector128.Create(0x1f83d9abu),
                Vector128.Create(0x5be0cd19u)
            };
            Span<bool> flags = stackalloc bool[4];
            SHADataContext[] contexts = new SHADataContext[4]
            {
                new SHADataContext(data1),
                new SHADataContext(data2),
                new SHADataContext(data3),
                new SHADataContext(data4)
            };

            Span<uint> block = stackalloc uint[16 * 4];

            Span<Vector128<uint>> schedule = stackalloc Vector128<uint>[64];

            byte[][] hashes = AllocateHashs(4, sizeof(uint) * 8);

            int concurrentHashes = 4, i;

            do
            {
                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock(MemoryMarshal.Cast<uint, byte>(block.Slice(i * 16, 16)));
                    }
                }

                InitScheduleSHA256Parallel(schedule, block);

                ProcessBlocksParallelSHA256(state, schedule);

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

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
                uint[] scalarSchedule = new uint[64];
                var dataBlock = MemoryMarshal.AsBytes(scalarSchedule.AsSpan(0, 16));

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                        continue;

                    Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);

                    ExtractHashFromState(state, hash, i);

                    do
                    {
                        ctx.PrepareBlock(dataBlock);

                        InitScheduleSHA256(scalarSchedule);

                        ProcessBlockSHA256(hash, scalarSchedule);

                    } while (!ctx.Complete);
                }
            }

            foreach (var hash in hashes)
            {
                Span<uint> hashSpan = MemoryMarshal.Cast<byte, uint>(hash);
                ReverseEndianess(hashSpan);
            }

            return hashes;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void ProcessBlocksParallelSHA256(Span<Vector128<uint>> state, Span<Vector128<uint>> schedule)
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

            fixed (Vector128<uint>* schedule_ptr = schedule)
            fixed (uint* tableK = SHA256TableK)
            {
                for (int i = 0; i < 64; ++i)
                {
                    Vector128<uint> tmp1, tmp2, S0, S1;

                    //ch calculation
                    tmp1 = Sse2.And(e, f);
                    tmp1 = Sse2.Xor(tmp1, Sse2.AndNot(e, g));
                    
                    if (Avx2.IsSupported)
                    {
                        tmp2 = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        tmp2 = Vector128.Create(tableK[i]);
                    }
                    tmp1 = Sse2.Add(tmp1, tmp2);
                    tmp1 = Sse2.Add(tmp1, schedule_ptr[i]);
                    tmp1 = Sse2.Add(tmp1, h);

                    S1 = Sse2.Or(Sse2.ShiftRightLogical(e, 6), Sse2.ShiftLeftLogical(e, 32 - 6));
                    S1 = Sse2.Xor(S1, Sse2.Or(Sse2.ShiftRightLogical(e, 11), Sse2.ShiftLeftLogical(e, 32 - 11)));
                    S1 = Sse2.Xor(S1, Sse2.Or(Sse2.ShiftRightLogical(e, 25), Sse2.ShiftLeftLogical(e, 32 - 25)));
                    tmp1 = Sse2.Add(tmp1, S1);

                    //maj calculation
                    tmp2 = Sse2.And(a, b);
                    tmp2 = Sse2.Xor(tmp2, Sse2.And(a, c));
                    tmp2 = Sse2.Xor(tmp2, Sse2.And(b, c));

                    S0 = Sse2.Or(Sse2.ShiftRightLogical(a, 2), Sse2.ShiftLeftLogical(a, 32 - 2));
                    S0 = Sse2.Xor(S0, Sse2.Or(Sse2.ShiftRightLogical(a, 13), Sse2.ShiftLeftLogical(a, 32 - 13)));
                    S0 = Sse2.Xor(S0, Sse2.Or(Sse2.ShiftRightLogical(a, 22), Sse2.ShiftLeftLogical(a, 32 - 22)));

                    tmp2 = Sse2.Add(tmp2, S0);

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

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void InitScheduleSHA256Parallel(Span<Vector128<uint>> schedule, Span<uint> block)
        {
            fixed (Vector128<uint>* schedulePtr = schedule)
            {
                fixed (uint* blockPtr = block)
                {
                    if (Avx2.IsSupported)
                    {
                        var offsets = Vector128.Create(0, 16, 16 * 2, 16 * 3);

                        for (int i = 0; i < 16; ++i)
                        {
                            var idx = Vector128.Create(i);
                            idx = Sse2.Add(idx, offsets);

                            var vec = Avx2.GatherVector128(blockPtr, idx, 4);

                            vec = Ssse3.Shuffle(vec.AsByte(), ReverseEndianess_32_128).AsUInt32();

                            schedulePtr[i] = vec;
                        }
                    }
                    else
                    {
                        uint* scheduleptr = (uint*)schedulePtr;

                        for (int i = 0; i < 16; ++i)
                        {
                            var tptr = scheduleptr + (i * 4);

                            tptr[0] = BinaryPrimitives.ReverseEndianness(blockPtr[i]);
                            tptr[1] = BinaryPrimitives.ReverseEndianness(blockPtr[i + 16]);
                            tptr[2] = BinaryPrimitives.ReverseEndianness(blockPtr[i + 16 * 2]);
                            tptr[3] = BinaryPrimitives.ReverseEndianness(blockPtr[i + 16 * 3]);
                        }
                    }
                }

                for (int i = 16; i < 64; ++i)
                {
                    //var tmp = chunk[i - 15];
                    //var s0 = BitOperations.RotateRight(tmp, 7) ^ BitOperations.RotateRight(tmp, 18) ^ (tmp >> 3);

                    var tmp = schedulePtr[i - 15];

                    var t0 = Sse2.ShiftRightLogical(tmp, 7);
                    var t1 = Sse2.ShiftLeftLogical(tmp, 32 - 7);
                    var S0 = Sse2.Or(t0, t1);

                    t0 = Sse2.ShiftRightLogical(tmp, 18);
                    t1 = Sse2.ShiftLeftLogical(tmp, 32 - 18);
                    t0 = Sse2.Or(t0, t1);
                    S0 = Sse2.Xor(S0, t0);

                    t0 = Sse2.ShiftRightLogical(tmp, 3);
                    S0 = Sse2.Xor(S0, t0);

                    //tmp = chunk[i - 2];
                    //var s1 = BitOperations.RotateRight(tmp, 17) ^ BitOperations.RotateRight(tmp, 19) ^ (tmp >> 10);

                    tmp = schedulePtr[i - 2];

                    t0 = Sse2.ShiftRightLogical(tmp, 17);
                    t1 = Sse2.ShiftLeftLogical(tmp, 32 - 17);
                    var S1 = Sse2.Or(t0, t1);

                    t0 = Sse2.ShiftRightLogical(tmp, 19);
                    t1 = Sse2.ShiftLeftLogical(tmp, 32 - 19);
                    t0 = Sse2.Or(t0, t1);
                    S1 = Sse2.Xor(S1, t0);

                    t0 = Sse2.ShiftRightLogical(tmp, 10);
                    S1 = Sse2.Xor(S1, t0);

                    //chunk[i] = chunk[i - 16] + s0 + chunk[i - 7] + s1;

                    tmp = Sse2.Add(S0, schedulePtr[i - 16]);
                    tmp = Sse2.Add(tmp, schedulePtr[i - 7]);
                    tmp = Sse2.Add(tmp, S1);

                    schedulePtr[i] = tmp;
                }
            }
        }
    }
}
