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
        public static byte[] SHA512(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data, SHADataContext.AlgorithmWordSize._64);

            ulong* state = stackalloc ulong[8] 
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

            ulong* schedule = stackalloc ulong[80];

            do
            {
                ctx.PrepareBlock((byte*)schedule, sizeof(ulong) * 16);
                InitScheduleSHA512(schedule);
                ProcessBlockSHA512(state, schedule);
            }
            while (!ctx.Complete);

            if (BitConverter.IsLittleEndian)
            {
                var hash = new byte[8 * sizeof(ulong)];

                if (Avx2.IsSupported)
                {
                    Vector256<ulong> vec = Avx2.LoadVector256(state), vec2 = Avx2.LoadVector256(state + 4);

                    Unsafe.As<byte, Vector256<byte>>(ref hash[0]) = Avx2.Shuffle(vec.AsByte(), ReverseEndianess_64_256);
                    Unsafe.As<byte, Vector256<byte>>(ref hash[sizeof(ulong) * 4]) = Avx2.Shuffle(vec2.AsByte(), ReverseEndianess_64_256);
                }
                else
                {
                    fixed (byte* phash = hash)
                        ReverseEndianess(state, (ulong*)phash, 8);
                }

                return hash;
            }
            else
            {
                return new Span<byte>(state, sizeof(ulong) * 8).ToArray();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static byte[][] SHA512Parallel(byte[] data1, byte[] data2)
        {
            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException(SSE2_NotAvailable);
            }

            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
            }

            Vector128<ulong>* state = stackalloc Vector128<ulong>[8]
            {
                Vector128.Create(0x6a09e667f3bcc908u),
                Vector128.Create(0xbb67ae8584caa73bu),
                Vector128.Create(0x3c6ef372fe94f82bu),
                Vector128.Create(0xa54ff53a5f1d36f1u),
                Vector128.Create(0x510e527fade682d1u),
                Vector128.Create(0x9b05688c2b3e6c1fu),
                Vector128.Create(0x1f83d9abfb41bd6bu),
                Vector128.Create(0x5be0cd19137e2179u)
            };

            ulong* blocks = stackalloc ulong[16 * 2];

            Vector128<ulong>* schedule = stackalloc Vector128<ulong>[80];

            bool* flags = stackalloc bool[Vector128<ulong>.Count];

            SHADataContext[] contexts = new SHADataContext[2]
            {
                new SHADataContext(data1, SHADataContext.AlgorithmWordSize._64),
                new SHADataContext(data2, SHADataContext.AlgorithmWordSize._64)
            };

            byte[][] hashes = AllocateHashs(2, sizeof(ulong) * 8);

            int concurrentHashes = 2, i;

            do
            {
                for (i = 0; i < 2; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock((byte*)(blocks + i * 16), sizeof(ulong) * 16);
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

                        fixed (byte* hash = hashes[i])
                        {
                            ExtractHashState_SHA512(state, (ulong*)hash, i);
                        }

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 1);

            if (concurrentHashes > 0)
            {
                Span<byte> dataBlock = new Span<byte>(schedule, sizeof(ulong) * 16);

                for (i = 0; i < 2; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                    {
                        continue;
                    }

                    fixed (byte* hash = hashes[i])
                    {
                        ExtractHashState_SHA512(state, (ulong*)hash, i);

                        do
                        {
                            ctx.PrepareBlock((byte*)schedule, sizeof(ulong) * 16);

                            InitScheduleSHA512((ulong*)schedule);

                            ProcessBlockSHA512((ulong*)hash, (ulong*)schedule);

                        } while (!ctx.Complete);
                    }
                }
            }

            foreach (var hash in hashes)
            {
                fixed (byte* phash = hash)
                    ReverseEndianess((ulong*)phash, 8);
            }

            return hashes;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static byte[][] SHA512Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!Avx2.IsSupported)
            {
                throw new NotSupportedException(AVX2_NotAvailable);
            }

            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
            }

            Vector256<ulong>* state = stackalloc Vector256<ulong>[8]
            {
                Vector256.Create(0x6a09e667f3bcc908u),
                Vector256.Create(0xbb67ae8584caa73bu),
                Vector256.Create(0x3c6ef372fe94f82bu),
                Vector256.Create(0xa54ff53a5f1d36f1u),
                Vector256.Create(0x510e527fade682d1u),
                Vector256.Create(0x9b05688c2b3e6c1fu),
                Vector256.Create(0x1f83d9abfb41bd6bu),
                Vector256.Create(0x5be0cd19137e2179u)
            };

            ulong* blocks = stackalloc ulong[16 * 4];
            Vector256<ulong>* schedule = stackalloc Vector256<ulong>[80];

            bool* flags = stackalloc bool[4];
            SHADataContext[] contexts = new SHADataContext[4]
            {
                new SHADataContext(data1, SHADataContext.AlgorithmWordSize._64),
                new SHADataContext(data2, SHADataContext.AlgorithmWordSize._64),
                new SHADataContext(data3, SHADataContext.AlgorithmWordSize._64),
                new SHADataContext(data4, SHADataContext.AlgorithmWordSize._64)
            };

            byte[][] hashes = AllocateHashs(4, sizeof(ulong) * 8);

            int concurrentHashes = 4, i;

            do
            {
                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock((byte*)(blocks + i * 16), sizeof(ulong) * 16);
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

                        fixed (byte* hash = hashes[i])
                        {
                            ExtractHashState_SHA512(state, (ulong*)hash, i);
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
                    {
                        continue;
                    }

                    fixed (byte* hash = hashes[i])
                    {
                        ExtractHashState_SHA512(state, (ulong*)hash, i);

                        do
                        {
                            ctx.PrepareBlock((byte*)schedule, sizeof(ulong) * 16);

                            InitScheduleSHA512((ulong*)schedule);

                            ProcessBlockSHA512((ulong*)hash, (ulong*)schedule);

                        } while (!ctx.Complete);
                    }
                }
            }

            foreach (var hash in hashes)
            {
                fixed (byte* phash = hash)
                    ReverseEndianess((ulong*)phash, 8);
            }

            return hashes;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void ProcessBlockSHA512(ulong* state, ulong* schedule)
        {
            fixed (ulong* tableK = SHA512TableK)
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
                    var tmp1 = h + S1 + ch + tableK[i] + schedule[i];
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
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void ProcessBlocksParallelSHA512(Vector128<ulong>* state, Vector128<ulong>* schedule)
        {
            Vector128<ulong> a, b, c, d, e, f, g, h;

            fixed (ulong* tableK = SHA512TableK)
            {
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
                    Vector128<ulong> tmp1, tmp2, S, ch;

                    if (Avx2.IsSupported)
                    {
                        tmp1 = Avx2.BroadcastScalarToVector128(tableK + i);
                    }
                    else
                    {
                        tmp1 = Vector128.Create(tableK[i]);
                    }

                    tmp1 = Sse2.Add(tmp1, schedule[i]);
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

                state[0] = Sse2.Add(a, state[0]);
                state[1] = Sse2.Add(b, state[1]);
                state[2] = Sse2.Add(c, state[2]);
                state[3] = Sse2.Add(d, state[3]);
                state[4] = Sse2.Add(e, state[4]);
                state[5] = Sse2.Add(f, state[5]);
                state[6] = Sse2.Add(g, state[6]);
                state[7] = Sse2.Add(h, state[7]);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void ProcessBlocksParallelSHA512(Vector256<ulong>* state, Vector256<ulong>* schedule)
        {
            Vector256<ulong> a, b, c, d, e, f, g, h;

            fixed (ulong* tableK = SHA512TableK)
            {
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
                    tmp1 = Avx2.Add(tmp1, schedule[i]);
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

                state[0] = Avx2.Add(a, state[0]);
                state[1] = Avx2.Add(b, state[1]);
                state[2] = Avx2.Add(c, state[2]);
                state[3] = Avx2.Add(d, state[3]);
                state[4] = Avx2.Add(e, state[4]);
                state[5] = Avx2.Add(f, state[5]);
                state[6] = Avx2.Add(g, state[6]);
                state[7] = Avx2.Add(h, state[7]);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void InitScheduleSHA512(ulong* schedule)
        {
            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(schedule, 16);
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

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void InitScheduleSHA512Parallel(Vector128<ulong>* schedule, ulong* block)
        {
            if (Avx2.IsSupported)
            {
                for (int i = 0; i < 16; ++i)
                {
                    var idx = Vector128.Create((long)i);
                    idx = Sse2.Add(idx, GatherIndex_64_128);

                    var vec = Avx2.GatherVector128(block, idx, 8);

                    vec = Ssse3.Shuffle(vec.AsByte(), ReverseEndianess_64_128).AsUInt64();

                    schedule[i] = vec;
                }
            }
            else
            {
                ulong* scheduleptr = (ulong*)schedule;

                for (int i = 0; i < 16; ++i)
                {
                    var tptr = scheduleptr + (i * 2);

                    tptr[0] = BinaryPrimitives.ReverseEndianness(block[i]);
                    tptr[1] = BinaryPrimitives.ReverseEndianness(block[i + 16]);
                }
            }

            for (int i = 16; i < 80; ++i)
            {
                //var tmp = chunk[i - 15];
                //var s0 = BitOperations.RotateRight(tmp, 7) ^ BitOperations.RotateRight(tmp, 18) ^ (tmp >> 3);

                var tmp = schedule[i - 15];

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

                tmp = schedule[i - 2];

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

                tmp = Sse2.Add(S0, schedule[i - 16]);
                tmp = Sse2.Add(tmp, schedule[i - 7]);
                tmp = Sse2.Add(tmp, S1);

                schedule[i] = tmp;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void InitScheduleSHA512Parallel(Vector256<ulong>* schedule, ulong* block)
        {
            for (int i = 0; i < 16; ++i)
            {
                var idx = Vector256.Create((long)i);
                idx = Avx2.Add(idx, GatherIndex_64_256);

                var vec = Avx2.GatherVector256(block, idx, 8);

                vec = Avx2.Shuffle(vec.AsByte(), ReverseEndianess_64_256).AsUInt64();

                schedule[i] = vec;
            }

            for (int i = 16; i < 80; ++i)
            {
                //var tmp = chunk[i - 15];
                //var s0 = BitOperations.RotateRight(tmp, 7) ^ BitOperations.RotateRight(tmp, 18) ^ (tmp >> 3);

                var tmp = schedule[i - 15];

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

                tmp = schedule[i - 2];

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

                tmp = Avx2.Add(S0, schedule[i - 16]);
                tmp = Avx2.Add(tmp, schedule[i - 7]);
                tmp = Avx2.Add(tmp, S1);

                schedule[i] = tmp;
            }
        }

        private static void ExtractHashState_SHA512(Vector128<ulong>* state, ulong* hash, int hashIdx)
        {
            Debug.Assert(hashIdx < Vector128<ulong>.Count);

            ulong* stateScalar = (ulong*)state;

            for (int i = 0; i < 8; ++i)
            {
                hash[i] = stateScalar[Vector128<ulong>.Count * i + hashIdx];
            }
        }

        private static void ExtractHashState_SHA512(Vector256<ulong>* state, ulong* hash, int hashIdx)
        {
            Debug.Assert(hashIdx < Vector256<ulong>.Count);

            ulong* stateScalar = (ulong*)state;

            for (int i = 0; i < 8; ++i)
            {
                hash[i] = stateScalar[Vector256<ulong>.Count * i + hashIdx];
            }
        }
    }
}
