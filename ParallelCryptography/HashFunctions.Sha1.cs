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

            const int blockSize = 16 * 4;
            const int scheduleSize = 80 * 4;

            var scheduleMemory = MemoryPool.Rent(scheduleSize);
            var blockMemory = MemoryPool.Rent(blockSize);

            Span<uint> block = blockMemory.Memory.Span;
            Span<Vector128<uint>> schedule = MemoryMarshal.Cast<uint, Vector128<uint>>(scheduleMemory.Memory.Span);

            byte[][] hashes = AllocateHashs(4, sizeof(uint) * 5);

            state[0] = Vector128.Create(0x67452301u);
            state[1] = Vector128.Create(0xEFCDAB89u);
            state[2] = Vector128.Create(0x98BADCFEu);
            state[3] = Vector128.Create(0x10325476u);
            state[4] = Vector128.Create(0xC3D2E1F0u);

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

                InitScheduleSHA1Parallel(schedule, block);

                ProcessBlocksParallelSHA1(state, schedule);

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
                uint[] scalarSchedule = new uint[80];
                Span<byte> dataBlock = MemoryMarshal.AsBytes(scalarSchedule.AsSpan(0, 16));

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

                        InitScheduleSHA1(scalarSchedule);

                        ProcessBlockSHA1(hash, scalarSchedule);

                    } while (!ctx.Complete);
                }
            }

            blockMemory.Dispose();
            scheduleMemory.Dispose();

            //Hash byte order correction
            if (BitConverter.IsLittleEndian)
            {
                foreach (var hash in hashes)
                {
                    ReverseEndianess(MemoryMarshal.Cast<byte, uint>(hash));
                }
            }

            return hashes;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void InitScheduleSHA1(Span<uint> schedule)
        {
            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(schedule.Slice(0, 16));
            }

            if (Sse2.IsSupported)
            {
                fixed (uint* dest = schedule)
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
                    schedule[i] = BitOperations.RotateLeft(schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16], 1);
                }
            }
        }

        private static unsafe void InitScheduleSHA1Parallel(Span<Vector128<uint>> schedule, Span<uint> block)
        {
            if (block.Length < 16 * 4)
            {
                throw new ArgumentException();
            }

            if (schedule.Length < 80)
            {
                throw new ArgumentException();
            }

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

                            if (BitConverter.IsLittleEndian)
                            {
                                vec = Ssse3.Shuffle(vec.AsByte(), EndianessReverseShuffleConstant).AsUInt32();
                            }

                            schedulePtr[i] = vec;
                        }
                    }
                    else
                    {
                        uint* scheduleptr = (uint*)schedulePtr;

                        for (int i = 0; i < 16; ++i)
                        {
                            var tptr = scheduleptr + (i * 4);

                            if (BitConverter.IsLittleEndian)
                            {
                                tptr[0] = BinaryPrimitives.ReverseEndianness(blockPtr[i]);
                                tptr[1] = BinaryPrimitives.ReverseEndianness(blockPtr[i + 16]);
                                tptr[2] = BinaryPrimitives.ReverseEndianness(blockPtr[i + 16 * 2]);
                                tptr[3] = BinaryPrimitives.ReverseEndianness(blockPtr[i + 16 * 3]);
                            }
                            else
                            {
                                tptr[0] = blockPtr[i];
                                tptr[1] = blockPtr[i + 16];
                                tptr[2] = blockPtr[i + 16 * 2];
                                tptr[3] = blockPtr[i + 16 * 3];
                            }
                        }
                    }
                }

                for (int i = 16; i < 80; ++i)
                {
                    var res = schedulePtr[i - 16];
                    res = Sse2.Xor(res, schedulePtr[i - 14]);
                    res = Sse2.Xor(res, schedulePtr[i - 8]);
                    res = Sse2.Xor(res, schedulePtr[i - 3]);

                    var rolltmp = Sse2.ShiftRightLogical(res, 31);
                    res = Sse2.ShiftLeftLogical(res, 1);
                    res = Sse2.Or(res, rolltmp);

                    schedulePtr[i] = res;
                }
            }

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

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void ProcessBlocksParallelSHA1(Span<Vector128<uint>> state, Span<Vector128<uint>> chunkData)
        {
            Debug.Assert(state.Length == 5);
            Debug.Assert(chunkData.Length >= 80);

            Vector128<uint> a, b, c, d, e;

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];


            fixed (Vector128<uint>* chunk = chunkData)
            {
                int i = 0;

                Vector128<uint> f, t, k;
                k = Vector128.Create(0x5A827999u);

                while (i < 20)
                {
                    t = Sse2.Xor(c, d);
                    t = Sse2.And(t, b);
                    t = Sse2.Xor(t, d);

                    t = Sse2.Add(t, chunk[i]);
                    t = Sse2.Add(t, e);
                    t = Sse2.Add(t, k);
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
                    t = Sse2.Xor(b, c);
                    t = Sse2.Xor(t, d);

                    t = Sse2.Add(t, chunk[i]);
                    t = Sse2.Add(t, e);
                    t = Sse2.Add(t, k);
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
                    t = Sse2.And(b, c);
                    t = Sse2.Or(t, Sse2.And(b, d));
                    t = Sse2.Or(t, Sse2.And(c, d));

                    t = Sse2.Add(t, chunk[i]);
                    t = Sse2.Add(t, k);
                    t = Sse2.Add(t, e);
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
                    t = Sse2.Xor(b, c);
                    t = Sse2.Xor(t, d);

                    t = Sse2.Add(t, chunk[i]);
                    t = Sse2.Add(t, e);
                    t = Sse2.Add(t, k);
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
