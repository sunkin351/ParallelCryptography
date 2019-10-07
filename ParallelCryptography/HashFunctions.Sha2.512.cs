using System;
using System.Buffers;
using System.Buffers.Binary;
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
                throw new NotSupportedException(SSE2_NotAvailable);
            }

            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
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
            var blockMemory = MemoryPool<ulong>.Shared.Rent(16 * 2);

            Span<Vector128<ulong>> schedule = MemoryMarshal.Cast<ulong, Vector128<ulong>>(scheduleMemory.Memory.Span);
            Span<ulong> blocks = blockMemory.Memory.Span;

            byte[][] hashes = AllocateHashs(2, sizeof(ulong) * 8);

            int concurrentHashes = 2, i;

            do
            {
                for (i = 0; i < 2; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock(MemoryMarshal.AsBytes(blocks.Slice(i * 16, 16)));
                    }
                }

                InitScheduleSHA512Parallel(schedule, blocks);

                ProcessBlocksParallelSHA512(state, schedule);

                for (i = 0; i < 2; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        Span<ulong> hash = MemoryMarshal.Cast<byte, ulong>(hashes[i]);

                        ExtractHashFromState(state, hash, i);

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 1);

            if (concurrentHashes > 0)
            {
                Span<ulong> scalarSchedule = scheduleMemory.Memory.Span.Slice(0, 80);
                Span<byte> dataBlock = MemoryMarshal.AsBytes(scalarSchedule.Slice(0, 16));

                for (i = 0; i < 2; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                    {
                        continue;
                    }

                    Span<ulong> hash = MemoryMarshal.Cast<byte, ulong>(hashes[i]);

                    ExtractHashFromState(state, hash, i);

                    do
                    {
                        ctx.PrepareBlock(dataBlock);

                        InitScheduleSHA512(scalarSchedule);

                        ProcessBlockSHA512(hash, scalarSchedule);

                    } while (!ctx.Complete);
                }
            }

            scheduleMemory.Dispose();
            blockMemory.Dispose();

            foreach (var hash in hashes)
            {
                Span<ulong> hashSpan = MemoryMarshal.Cast<byte, ulong>(hash);
                ReverseEndianess(hashSpan);
            }

            return hashes;
        }

        public static byte[][] Sha512Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!Avx2.IsSupported)
            {
                throw new NotSupportedException(AVX2_NotAvailable);
            }

            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
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

            var blockMemory = MemoryPool<ulong>.Shared.Rent(16 * 4);
            var scheduleMemory = MemoryPool<ulong>.Shared.Rent(80 * 4);

            Span<ulong> blocks = blockMemory.Memory.Span;
            Span<Vector256<ulong>> schedule = MemoryMarshal.Cast<ulong, Vector256<ulong>>(scheduleMemory.Memory.Span);

            byte[][] hashes = AllocateHashs(4, sizeof(ulong) * 8);

            int concurrentHashes = 4, i;

            do
            {
                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock(MemoryMarshal.AsBytes(blocks.Slice(i * 16, 16)));
                    }
                }

                InitScheduleSHA512Parallel(schedule, blocks);

                ProcessBlocksParallelSHA512(state, schedule);

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        Span<ulong> hash = MemoryMarshal.Cast<byte, ulong>(hashes[i]);

                        ExtractHashFromState(state, hash, i);

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 2);

            if (concurrentHashes > 0)
            {
                Span<ulong> scalarSchedule = scheduleMemory.Memory.Span.Slice(0, 80);
                var dataBlock = MemoryMarshal.AsBytes(scalarSchedule.Slice(0, 16));

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                    {
                        continue;
                    }

                    Span<ulong> hash = MemoryMarshal.Cast<byte, ulong>(hashes[i]);

                    ExtractHashFromState(state, hash, i);

                    do
                    {
                        ctx.PrepareBlock(dataBlock);

                        InitScheduleSHA512(scalarSchedule);

                        ProcessBlockSHA512(hash, scalarSchedule);

                    } while (!ctx.Complete);
                }
            }

            blockMemory.Dispose();
            scheduleMemory.Dispose();

            foreach (var hash in hashes)
            {
                Span<ulong> hashSpan = MemoryMarshal.Cast<byte, ulong>(hash);
                ReverseEndianess(hashSpan);
            }

            return hashes;
        }

        private static unsafe void ProcessBlockSHA512(Span<ulong> state, Span<ulong> schedule)
        {
            if (state.Length < 8 || schedule.Length < 80)
                throw new ArgumentException();

            fixed (ulong* statePtr = state, schedulePtr = schedule, tableK = SHA512TableK)
            {
                ulong a, b, c, d, e, f, g, h;

                a = statePtr[0];
                b = statePtr[1];
                c = statePtr[2];
                d = statePtr[3];
                e = statePtr[4];
                f = statePtr[5];
                g = statePtr[6];
                h = statePtr[7];

                for (int i = 0; i < 80; ++i)
                {
                    var ch = (e & f) ^ (~e & g);
                    var maj = (a & b) ^ (a & c) ^ (b & c);
                    var S0 = BitOperations.RotateRight(a, 28) ^ BitOperations.RotateRight(a, 34) ^ BitOperations.RotateRight(a, 39);
                    var S1 = BitOperations.RotateRight(e, 14) ^ BitOperations.RotateRight(e, 18) ^ BitOperations.RotateRight(e, 41);
                    var tmp1 = h + S1 + ch + tableK[i] + schedulePtr[i];
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

                statePtr[0] += a;
                statePtr[1] += b;
                statePtr[2] += c;
                statePtr[3] += d;
                statePtr[4] += e;
                statePtr[5] += f;
                statePtr[6] += g;
                statePtr[7] += h;
            }
        }

        private static unsafe void ProcessBlocksParallelSHA512(Span<Vector128<ulong>> state, Span<Vector128<ulong>> schedule)
        {
            Vector128<ulong> a, b, c, d, e, f, g, h;

            if (state.Length < 8 || schedule.Length < 80)
                throw new ArgumentException();

            fixed (Vector128<ulong>* statePtr = state, schedulePtr = schedule)
            fixed (ulong* tableK = SHA512TableK)
            {
                a = statePtr[0];
                b = statePtr[1];
                c = statePtr[2];
                d = statePtr[3];
                e = statePtr[4];
                f = statePtr[5];
                g = statePtr[6];
                h = statePtr[7];

                for (int i = 0; i < 80; ++i)
                {
                    Vector128<ulong> tmp1, tmp2, S, ch;

                    if (Avx2.IsSupported)
                    {
                        tmp1 = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        tmp1 = Vector128.Create(tableK[i]);
                    }

                    tmp1 = Sse2.Add(tmp1, schedulePtr[i]);
                    tmp1 = Sse2.Add(tmp1, h);

                    //if (Avx2.IsSupported)
                    //{
                    //    var idx = Sse2.Add(Vector128.Create((long)i), Sha512GatherIndex_128);
                    //    tmp1 = Avx2.GatherVector128(schedulePtr, idx, 8);
                    //}
                    //else
                    //{
                    //    tmp1 = Vector128.Create(schedulePtr[i], schedulePtr[i + 80]);
                    //}

                    //var S0 = BitOperations.RotateRight(a, 28) ^ BitOperations.RotateRight(a, 34) ^ BitOperations.RotateRight(a, 39);
                    S = Sse2.Or(Sse2.ShiftRightLogical(e, 14), Sse2.ShiftLeftLogical(e, 64 - 14));
                    S = Sse2.Xor(S, Sse2.Or(Sse2.ShiftRightLogical(e, 18), Sse2.ShiftLeftLogical(e, 64 - 18)));
                    S = Sse2.Xor(S, Sse2.Or(Sse2.ShiftRightLogical(e, 41), Sse2.ShiftLeftLogical(e, 64 - 41)));

                    tmp1 = Sse2.Add(tmp1, S);

                    ch = Sse2.And(e, f);
                    ch = Sse2.Xor(ch, Sse2.AndNot(e, g));

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

                statePtr[0] = Sse2.Add(a, statePtr[0]);
                statePtr[1] = Sse2.Add(b, statePtr[1]);
                statePtr[2] = Sse2.Add(c, statePtr[2]);
                statePtr[3] = Sse2.Add(d, statePtr[3]);
                statePtr[4] = Sse2.Add(e, statePtr[4]);
                statePtr[5] = Sse2.Add(f, statePtr[5]);
                statePtr[6] = Sse2.Add(g, statePtr[6]);
                statePtr[7] = Sse2.Add(h, statePtr[7]);
            }
        }

        private static unsafe void ProcessBlocksParallelSHA512(Span<Vector256<ulong>> state, Span<Vector256<ulong>> schedule)
        {
            if (state.Length < 8 || schedule.Length < 80)
                throw new ArgumentException();

            Vector256<ulong> a, b, c, d, e, f, g, h;

            fixed (Vector256<ulong>* statePtr = state, schedulePtr = schedule)
            fixed (ulong* tableK = SHA512TableK)
            {
                a = statePtr[0];
                b = statePtr[1];
                c = statePtr[2];
                d = statePtr[3];
                e = statePtr[4];
                f = statePtr[5];
                g = statePtr[6];
                h = statePtr[7];

                for (int i = 0; i < 80; ++i)
                {
                    Vector256<ulong> tmp1, tmp2, S, ch;

                    ch = Avx2.And(e, f);
                    ch = Avx2.Xor(ch, Avx2.AndNot(e, g));

                    //maj calculated in-place
                    tmp2 = Avx2.And(a, b);
                    tmp2 = Avx2.Xor(tmp2, Avx2.And(a, c));
                    tmp2 = Avx2.Xor(tmp2, Avx2.And(b, c));

                    S = Avx2.Or(Avx2.ShiftRightLogical(a, 28), Avx2.ShiftLeftLogical(a, 64 - 28));
                    S = Avx2.Xor(S, Avx2.Or(Avx2.ShiftRightLogical(a, 34), Avx2.ShiftLeftLogical(a, 64 - 34)));
                    S = Avx2.Xor(S, Avx2.Or(Avx2.ShiftRightLogical(a, 39), Avx2.ShiftLeftLogical(a, 64 - 39)));

                    tmp2 = Avx2.Add(tmp2, S);

                    S = Avx2.Or(Avx2.ShiftRightLogical(e, 14), Avx2.ShiftLeftLogical(e, 64 - 14));
                    S = Avx2.Xor(S, Avx2.Or(Avx2.ShiftRightLogical(e, 18), Avx2.ShiftLeftLogical(e, 64 - 18)));
                    S = Avx2.Xor(S, Avx2.Or(Avx2.ShiftRightLogical(e, 41), Avx2.ShiftLeftLogical(e, 64 - 41)));

                    tmp1 = Avx2.BroadcastScalarToVector256(tableK + i);
                    tmp1 = Avx2.Add(tmp1, schedulePtr[i]);
                    tmp1 = Avx2.Add(tmp1, S);
                    tmp1 = Avx2.Add(tmp1, ch);
                    tmp1 = Avx2.Add(tmp1, h);

                    h = g;
                    g = f;
                    f = e;
                    e = Avx2.Add(d, tmp1);
                    d = c;
                    c = b;
                    b = a;
                    a = Avx2.Add(tmp1, tmp2);
                }

                statePtr[0] = Avx2.Add(a, statePtr[0]);
                statePtr[1] = Avx2.Add(b, statePtr[1]);
                statePtr[2] = Avx2.Add(c, statePtr[2]);
                statePtr[3] = Avx2.Add(d, statePtr[3]);
                statePtr[4] = Avx2.Add(e, statePtr[4]);
                statePtr[5] = Avx2.Add(f, statePtr[5]);
                statePtr[6] = Avx2.Add(g, statePtr[6]);
                statePtr[7] = Avx2.Add(h, statePtr[7]);
            }
        }

        public static unsafe void InitScheduleSHA512(Span<ulong> schedule)
        {
            fixed (ulong* schedulePtr = schedule)
            {
                if (BitConverter.IsLittleEndian)
                {
                    for (int i = 0; i < 16; ++i)
                    {
                        schedulePtr[i] = BinaryPrimitives.ReverseEndianness(schedulePtr[i]);
                    }
                }

                for (int i = 16; i < 80; ++i)
                {
                    var tmp = schedulePtr[i - 15];
                    var s0 = BitOperations.RotateRight(tmp, 1) ^ BitOperations.RotateRight(tmp, 8) ^ (tmp >> 7);

                    tmp = schedulePtr[i - 2];
                    var s1 = BitOperations.RotateRight(tmp, 19) ^ BitOperations.RotateRight(tmp, 61) ^ (tmp >> 6);

                    schedulePtr[i] = schedulePtr[i - 16] + s0 + schedulePtr[i - 7] + s1;
                }
            }
        }

        public static unsafe void InitScheduleSHA512Parallel(Span<Vector128<ulong>> schedule, Span<ulong> block)
        {
            fixed (Vector128<ulong>* schedulePtr = schedule)
            {
                fixed (ulong* blockPtr = block)
                {
                    if (Avx2.IsSupported)
                    {
                        for (int i = 0; i < 16; ++i)
                        {
                            var idx = Vector128.Create((long)i);
                            idx = Sse2.Add(idx, Sha512GatherIndex_128);

                            var vec = Avx2.GatherVector128(blockPtr, idx, 8);

                            vec = Ssse3.Shuffle(vec.AsByte(), Sha512ReverseEndianess_128).AsUInt64();

                            schedulePtr[i] = vec;
                        }
                    }
                    else
                    {
                        ulong* scheduleptr = (ulong*)schedulePtr;

                        for (int i = 0; i < 16; ++i)
                        {
                            var tptr = scheduleptr + (i * 2);

                            tptr[0] = BinaryPrimitives.ReverseEndianness(blockPtr[i]);
                            tptr[1] = BinaryPrimitives.ReverseEndianness(blockPtr[i + 16]);
                        }
                    }
                }

                for (int i = 16; i < 80; ++i)
                {
                    //var tmp = chunk[i - 15];
                    //var s0 = BitOperations.RotateRight(tmp, 7) ^ BitOperations.RotateRight(tmp, 18) ^ (tmp >> 3);

                    var tmp = schedulePtr[i - 15];

                    var t0 = Sse2.ShiftRightLogical(tmp, 1);
                    var t1 = Sse2.ShiftLeftLogical(tmp, 64 - 1);
                    var S0 = Sse2.Or(t0, t1);

                    t0 = Sse2.ShiftRightLogical(tmp, 8);
                    t1 = Sse2.ShiftLeftLogical(tmp, 64 - 8);
                    t0 = Sse2.Or(t0, t1);
                    S0 = Sse2.Xor(S0, t0);

                    t0 = Sse2.ShiftRightLogical(tmp, 7);
                    S0 = Sse2.Xor(S0, t0);

                    //tmp = chunk[i - 2];
                    //var s1 = BitOperations.RotateRight(tmp, 17) ^ BitOperations.RotateRight(tmp, 19) ^ (tmp >> 10);

                    tmp = schedulePtr[i - 2];

                    t0 = Sse2.ShiftRightLogical(tmp, 19);
                    t1 = Sse2.ShiftLeftLogical(tmp, 64 - 19);
                    var S1 = Sse2.Or(t0, t1);

                    t0 = Sse2.ShiftRightLogical(tmp, 61);
                    t1 = Sse2.ShiftLeftLogical(tmp, 64 - 61);
                    t0 = Sse2.Or(t0, t1);
                    S1 = Sse2.Xor(S1, t0);

                    t0 = Sse2.ShiftRightLogical(tmp, 6);
                    S1 = Sse2.Xor(S1, t0);

                    //chunk[i] = chunk[i - 16] + s0 + chunk[i - 7] + s1;

                    tmp = Sse2.Add(S0, schedulePtr[i - 16]);
                    tmp = Sse2.Add(tmp, schedulePtr[i - 7]);
                    tmp = Sse2.Add(tmp, S1);

                    schedulePtr[i] = tmp;
                }
            }
        }

        public static unsafe void InitScheduleSHA512Parallel(Span<Vector256<ulong>> schedule, Span<ulong> block)
        {
            fixed (Vector256<ulong>* schedulePtr = schedule)
            {
                fixed (ulong* blockPtr = block)
                {
                    for (int i = 0; i < 16; ++i)
                    {
                        var idx = Vector256.Create((long)i);
                        idx = Avx2.Add(idx, Sha512GatherIndex_256);

                        var vec = Avx2.GatherVector256(blockPtr, idx, 8);

                        vec = Avx2.Shuffle(vec.AsByte(), Sha512ReverseEndianess_256).AsUInt64();

                        schedulePtr[i] = vec;
                    }
                }

                for (int i = 16; i < 80; ++i)
                {
                    //var tmp = chunk[i - 15];
                    //var s0 = BitOperations.RotateRight(tmp, 7) ^ BitOperations.RotateRight(tmp, 18) ^ (tmp >> 3);

                    var tmp = schedulePtr[i - 15];

                    var t0 = Avx2.ShiftRightLogical(tmp, 1);
                    var t1 = Avx2.ShiftLeftLogical(tmp, 64 - 1);
                    var S0 = Avx2.Or(t0, t1);

                    t0 = Avx2.ShiftRightLogical(tmp, 8);
                    t1 = Avx2.ShiftLeftLogical(tmp, 64 - 8);
                    t0 = Avx2.Or(t0, t1);
                    S0 = Avx2.Xor(S0, t0);

                    t0 = Avx2.ShiftRightLogical(tmp, 7);
                    S0 = Avx2.Xor(S0, t0);

                    //tmp = chunk[i - 2];
                    //var s1 = BitOperations.RotateRight(tmp, 17) ^ BitOperations.RotateRight(tmp, 19) ^ (tmp >> 10);

                    tmp = schedulePtr[i - 2];

                    t0 = Avx2.ShiftRightLogical(tmp, 19);
                    t1 = Avx2.ShiftLeftLogical(tmp, 64 - 19);
                    var S1 = Avx2.Or(t0, t1);

                    t0 = Avx2.ShiftRightLogical(tmp, 61);
                    t1 = Avx2.ShiftLeftLogical(tmp, 64 - 61);
                    t0 = Avx2.Or(t0, t1);
                    S1 = Avx2.Xor(S1, t0);

                    t0 = Avx2.ShiftRightLogical(tmp, 6);
                    S1 = Avx2.Xor(S1, t0);

                    //chunk[i] = chunk[i - 16] + s0 + chunk[i - 7] + s1;

                    tmp = Avx2.Add(S0, schedulePtr[i - 16]);
                    tmp = Avx2.Add(tmp, schedulePtr[i - 7]);
                    tmp = Avx2.Add(tmp, S1);

                    schedulePtr[i] = tmp;
                }
            }
        }
    }
}
