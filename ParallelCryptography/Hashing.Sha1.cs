using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Numerics;

namespace ParallelCryptography
{
    public static partial class HashFunctions
    {
        public static byte[] SHA1(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            byte[] hash = new byte[sizeof(uint) * 5];

            Span<uint> state = MemoryMarshal.Cast<byte, uint>(hash);

            SHA1InitState.AsSpan().CopyTo(state);

            var scheduleMemory = MemoryPool.Rent(80);
            Span<uint> schedule = scheduleMemory.Memory.Span;
            Span<byte> dataPortion = MemoryMarshal.Cast<uint, byte>(schedule.Slice(0, 16));

            do
            {
                ctx.PrepareBlock(dataPortion);
                InitScheduleSHA1(schedule);
                ProcessBlockSHA1(state, schedule);
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
        public static unsafe byte[][] SHA1Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException("SSE2 instructions not available");
            }

            Span<Vector128<uint>> state = stackalloc Vector128<uint>[5];
            Span<bool> flags = stackalloc bool[4];
            SHADataContext[] contexts = new SHADataContext[4];

            contexts[0] = new SHADataContext(data1);
            contexts[1] = new SHADataContext(data2);
            contexts[2] = new SHADataContext(data3);
            contexts[3] = new SHADataContext(data4);

            var scheduleMemory = MemoryPool.Rent(80 * 4);
            Span<uint> schedule = scheduleMemory.Memory.Span;

            byte[][] hashes = AllocateHashs(4, sizeof(uint) * 5);

            state[0] = Vector128.Create(0x67452301u);
            state[1] = Vector128.Create(0xEFCDAB89u);
            state[2] = Vector128.Create(0x98BADCFEu);
            state[3] = Vector128.Create(0x10325476u);
            state[4] = Vector128.Create(0xC3D2E1F0u);

            int concurrentHashes, i;

            do
            {
                concurrentHashes = 0;

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock(MemoryMarshal.Cast<uint, byte>(schedule.Slice(i * 80, 16)));
                        concurrentHashes += ctx.Complete ? 0 : 1;

                        InitScheduleSHA1(schedule.Slice(i * 80, 80));
                    }
                }

                ProcessBlocksParallelSHA1(state, schedule);

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

            for (i = 0; i < 4; ++i)
            {
                ref SHADataContext ctx = ref contexts[i];

                if (ctx.Complete)
                    continue;

                Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i]);
                Span<uint> block = schedule.Slice(0, 80);

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

            //Hash byte order correction
            if (BitConverter.IsLittleEndian)
            {
                foreach(var hash in hashes)
                {
                    ReverseEndianess(MemoryMarshal.Cast<byte, uint>(hash));
                }
            }

            return hashes;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void InitScheduleSHA1(Span<uint> chunk)
        {
            Debug.Assert(chunk.Length == 80);

            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(chunk.Slice(0, 16));
            }

            if (Sse2.IsSupported)
            {
                fixed (uint* dest = chunk)
                {
                    int i = 16;

                    while (i < 80)
                    {
                        Vector128<uint> tmp, tmp2;

                        tmp = Sse2.LoadVector128(dest + (i - 16));
                        tmp = Sse2.Xor(tmp, Sse2.LoadVector128(dest + (i - 14)));
                        tmp = Sse2.Xor(tmp, Sse2.LoadVector128(dest + (i - 8)));

                        if (Avx2.IsSupported)
                        {
                            tmp2 = Avx2.MaskLoad(dest + (i - 3), LoadMask);
                        }
                        else
                        {
                            tmp2 = Sse2.LoadVector128(dest + (i - 3));
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

                            Sse2.Store(dest + i, tmp);
                        }
                        else
                        {
                            Sse2.Store(dest + i, tmp);

                            dest[i + 3] = BitOperations.RotateLeft(dest[i], 1) ^ dest[i + 3];
                        }

                        i += 4;
                    }
                }
            }
            else
            {
                for (int i = 16; i < 80; ++i)
                {
                    chunk[i] = BitOperations.RotateLeft(chunk[i - 3] ^ chunk[i - 8] ^ chunk[i - 14] ^ chunk[i - 16], 1);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void ProcessBlocksParallelSHA1(Span<Vector128<uint>> state, Span<uint> chunkData)
        {
            Debug.Assert(state.Length == 5);
            Debug.Assert(chunkData.Length >= 80 * 4);

            Vector128<uint> a, b, c, d, e;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];

            Vector128<uint> f, t;

            fixed(uint* chunk = chunkData)
            {
                int i = 0;

                Vector128<uint> k = Vector128.Create(0x5A827999u);

                while (i < 20)
                {
                    f = Sse2.Xor(c, d);
                    f = Sse2.And(f, b);
                    f = Sse2.Xor(f, d);

                    if (Avx2.IsSupported)
                    {
                        Vector128<int> idx = Sse2.Add(Vector128.Create(i), SHA1GatherIndex);
                        t = Avx2.GatherVector128(chunk, idx, 4);
                    }
                    else
                    {
                        t = Vector128.Create(chunk[i], chunk[80 + i], chunk[80 * 2 + i], chunk[80 * 3 + i]);
                    }

                    t = Sse2.Add(t, k);
                    t = Sse2.Add(t, e);
                    t = Sse2.Add(t, f);
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
                    f = Sse2.Xor(b, c);
                    f = Sse2.Xor(f, d);

                    if (Avx2.IsSupported)
                    {
                        Vector128<int> idx = Sse2.Add(Vector128.Create(i), SHA1GatherIndex);
                        t = Avx2.GatherVector128(chunk, idx, 4);
                    }
                    else
                    {
                        t = Vector128.Create(chunk[i], chunk[80 + i], chunk[80 * 2 + i], chunk[80 * 3 + i]);
                    }

                    t = Sse2.Add(t, k);
                    t = Sse2.Add(t, e);
                    t = Sse2.Add(t, f);
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
                    f = Sse2.And(b, c);
                    f = Sse2.Or(f, Sse2.And(b, d));
                    f = Sse2.Or(f, Sse2.And(c, d));

                    if (Avx2.IsSupported)
                    {
                        Vector128<int> idx = Sse2.Add(Vector128.Create(i), SHA1GatherIndex);
                        t = Avx2.GatherVector128(chunk, idx, 4);
                    }
                    else
                    {
                        t = Vector128.Create(chunk[i], chunk[80 + i], chunk[80 * 2 + i], chunk[80 * 3 + i]);
                    }

                    t = Sse2.Add(t, k);
                    t = Sse2.Add(t, e);
                    t = Sse2.Add(t, f);
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
                    f = Sse2.Xor(b, c);
                    f = Sse2.Xor(f, d);

                    if (Avx2.IsSupported)
                    {
                        Vector128<int> idx = Sse2.Add(Vector128.Create(i), SHA1GatherIndex);
                        t = Avx2.GatherVector128(chunk, idx, 4);
                    }
                    else
                    {
                        t = Vector128.Create(chunk[i], chunk[80 + i], chunk[80 * 2 + i], chunk[80 * 3 + i]);
                    }

                    t = Sse2.Add(t, k);
                    t = Sse2.Add(t, e);
                    t = Sse2.Add(t, f);
                    t = Sse2.Add(t, RotateLeft5(a));

                    e = d;
                    d = c;
                    c = RotateLeft30(b);
                    b = a;
                    a = t;

                    i += 1;
                }
            }

            state[0] = Sse2.Add(a, state[0]);
            state[1] = Sse2.Add(b, state[1]);
            state[2] = Sse2.Add(c, state[2]);
            state[3] = Sse2.Add(d, state[3]);
            state[4] = Sse2.Add(e, state[4]);
        }

        private static void ProcessBlockSHA1(Span<uint> state, Span<uint> chunk)
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
    }
}
