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
        private static readonly ArrayPool<uint> poolMemory = ArrayPool<uint>.Create();

        private static readonly Vector128<int> GatherIndex = Vector128.Create(0, 80, 80 * 2, 80 * 3);
        private static readonly Vector128<byte> ShuffleConstant = Vector128.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
        private static readonly Vector128<uint> LoadMask = Vector128.Create(uint.MaxValue, uint.MaxValue, uint.MaxValue, 0);
        private static readonly uint[] InitState = new uint[5] { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static unsafe byte[][] SHA1Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            Span<Vector128<uint>> state = stackalloc Vector128<uint>[5];
            Span<bool> flags = stackalloc bool[4];
            SHA1DataContext[] contexts = new SHA1DataContext[4];

            uint[] chunkData = poolMemory.Rent(80 * 4);
            Span<uint> chunk = chunkData.AsSpan(0, 80 * 4);
            byte[][] hashes = new byte[4][];

            int i;

            for (i = 0; i < hashes.Length; ++i)
            {
                hashes[i] = new byte[sizeof(int) * 5];
            }

            state[0] = Vector128.Create(0x67452301u);
            state[1] = Vector128.Create(0xEFCDAB89u);
            state[2] = Vector128.Create(0x98BADCFEu);
            state[3] = Vector128.Create(0x10325476u);
            state[4] = Vector128.Create(0xC3D2E1F0u);

            contexts[0] = new SHA1DataContext(data1);
            contexts[1] = new SHA1DataContext(data2);
            contexts[2] = new SHA1DataContext(data3);
            contexts[3] = new SHA1DataContext(data4);

            int concurrentHashes;

            do
            {
                concurrentHashes = 0;

                for (i = 0; i < 4; ++i)
                {
                    ref SHA1DataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock(MemoryMarshal.Cast<uint, byte>(chunk.Slice(i * 80, 16)));
                        concurrentHashes += ctx.Complete ? 0 : 1;

                        InitChunk(chunk.Slice(i * 80, 80));
                    }
                }

                ProcessBlocksParallel(state, chunkData);

                for (i = 0; i < 4; ++i)
                {
                    ref SHA1DataContext ctx = ref contexts[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i + i]);

                        ExtractHashFromState(state, hash, i);
                    }
                }
            }
            while (concurrentHashes > 2);

            for (i = 0; i < 4; ++i)
            {
                ref SHA1DataContext ctx = ref contexts[i];

                if (ctx.Complete)
                    continue;

                Span<uint> hash = MemoryMarshal.Cast<byte, uint>(hashes[i + i]);
                Span<uint> block = chunk.Slice(0, 80);

                ExtractHashFromState(state, hash, i);

                var dataBlock = MemoryMarshal.Cast<uint, byte>(block.Slice(0, 16));

                do
                {
                    ctx.PrepareBlock(dataBlock);

                    InitChunk(block);

                    ProcessBlock(hash, block);

                } while (!ctx.Complete);
            }

            poolMemory.Return(chunkData);

            //Hash byte order correction
            if (BitConverter.IsLittleEndian)
            {
                foreach(var hash in hashes)
                {
                    if (Ssse3.IsSupported)
                    {
                        ref Vector128<byte> vec = ref Unsafe.As<byte, Vector128<byte>>(ref hash[0]);
                        vec = Ssse3.Shuffle(vec, ShuffleConstant);

                        ref uint tmp = ref Unsafe.Add(ref Unsafe.As<Vector128<byte>, uint>(ref vec), 4);

                        tmp = BinaryPrimitives.ReverseEndianness(tmp);
                    }
                    else
                    {
                        Span<uint> span = MemoryMarshal.Cast<byte, uint>(hash);

                        span[0] = BinaryPrimitives.ReverseEndianness(span[0]);
                        span[1] = BinaryPrimitives.ReverseEndianness(span[1]);
                        span[2] = BinaryPrimitives.ReverseEndianness(span[2]);
                        span[3] = BinaryPrimitives.ReverseEndianness(span[3]);
                        span[4] = BinaryPrimitives.ReverseEndianness(span[4]);
                    }
                }
            }

            return hashes;
        }

        public static byte[] SHA1(byte[] data)
        {
            SHA1DataContext ctx = new SHA1DataContext(data);

            byte[] hash = new byte[sizeof(uint) * 5];

            Span<uint> state = MemoryMarshal.CreateSpan(ref Unsafe.As<byte, uint>(ref hash[0]), 5);

            InitState.AsSpan().CopyTo(state);

            uint[] chunkMemory = poolMemory.Rent(80);
            Span<uint> chunk = chunkMemory.AsSpan(0, 80); //Chunk memory could be larger
            Span<byte> dataPortion = MemoryMarshal.Cast<uint, byte>(chunk.Slice(0, 16));

            do
            {
                ctx.PrepareBlock(dataPortion);
                InitChunk(chunk);
                ProcessBlock(state, chunk);
            }
            while (!ctx.Complete);

            poolMemory.Return(chunkMemory);

            if (BitConverter.IsLittleEndian)
            {
                if (Ssse3.IsSupported)
                {
                    ref Vector128<byte> vec = ref Unsafe.As<byte, Vector128<byte>>(ref hash[0]);
                    vec = Ssse3.Shuffle(vec, ShuffleConstant);

                    ref uint tmp = ref Unsafe.Add(ref Unsafe.As<Vector128<byte>, uint>(ref vec), 4);

                    tmp = BinaryPrimitives.ReverseEndianness(tmp);
                }
                else
                {
                    state[0] = BinaryPrimitives.ReverseEndianness(state[0]);
                    state[1] = BinaryPrimitives.ReverseEndianness(state[1]);
                    state[2] = BinaryPrimitives.ReverseEndianness(state[2]);
                    state[3] = BinaryPrimitives.ReverseEndianness(state[3]);
                    state[4] = BinaryPrimitives.ReverseEndianness(state[4]);
                }
            }

            return hash;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static unsafe void InitChunk(Span<uint> chunk)
        {
            Debug.Assert(chunk.Length == 80);

            if (BitConverter.IsLittleEndian)
            {
                for (int i = 0; i < 16; i += 4)
                {
                    if (Ssse3.IsSupported)
                    {
                        ref Vector128<uint> tmp = ref Unsafe.As<uint, Vector128<uint>>(ref chunk[i]);
                        tmp = Ssse3.Shuffle(tmp.AsByte(), ShuffleConstant).AsUInt32();
                    }
                    else
                    {
                        chunk[i] = BinaryPrimitives.ReverseEndianness(chunk[i]);
                        chunk[i + 1] = BinaryPrimitives.ReverseEndianness(chunk[i + 1]);
                        chunk[i + 2] = BinaryPrimitives.ReverseEndianness(chunk[i + 2]);
                        chunk[i + 3] = BinaryPrimitives.ReverseEndianness(chunk[i + 3]);
                    }
                }
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

                        tmp2 = Sse2.ShiftRightLogical(tmp, 31);
                        tmp = Sse2.ShiftLeftLogical(tmp, 1);
                        tmp = Sse2.Or(tmp, tmp2);

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
        private static unsafe void ProcessBlocksParallel(Span<Vector128<uint>> state, uint[] chunkData)
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
                        Vector128<int> idx = Sse2.Add(Vector128.Create(i), GatherIndex);
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
                        Vector128<int> idx = Sse2.Add(Vector128.Create(i), GatherIndex);
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
                        Vector128<int> idx = Sse2.Add(Vector128.Create(i), GatherIndex);
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
                        Vector128<int> idx = Sse2.Add(Vector128.Create(i), GatherIndex);
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

        private static void ProcessBlock(Span<uint> state, Span<uint> chunk)
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

        private static void ExtractHashFromState(Span<Vector128<uint>> state, Span<uint> hash, int hashIdx)
        {
            Debug.Assert(state.Length == 5);
            Debug.Assert(hash.Length == 5);
            Debug.Assert(hashIdx < 5);

            ref uint stateRef = ref Unsafe.As<Vector128<uint>, uint>(ref MemoryMarshal.GetReference(state));
            hash[0] = Unsafe.Add(ref stateRef, hashIdx);
            hash[1] = Unsafe.Add(ref stateRef, 4 + hashIdx);
            hash[2] = Unsafe.Add(ref stateRef, 4 * 2 + hashIdx);
            hash[3] = Unsafe.Add(ref stateRef, 4 * 3 + hashIdx);
            hash[4] = Unsafe.Add(ref stateRef, 4 * 4 + hashIdx);
        }

        [StructLayout(LayoutKind.Auto)]
        private struct SHA1DataContext
        {
            byte[] _data;
            int _dataidx;
            ulong _bitsize;
            bool appended;

            public bool Complete { get; private set; }

            public SHA1DataContext(byte[] data)
            {
                _data = data;
                _bitsize = data == null ? 0 : (ulong)data.Length * 8;
                _dataidx = 0;
                appended = false;
                Complete = false;
            }

            public void PrepareBlock(ref byte block)
            {
                int len = Math.Min(64, Length() - _dataidx);

                if (len == 0)
                {
                    if (!appended)
                    {
                        block = 0x80;
                        appended = true;
                    }

                    Unsafe.As<byte, ulong>(ref Unsafe.Add(ref block, 64 - 8)) = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(_bitsize) : _bitsize;
                    Complete = true;
                    return;
                }

                _data.AsSpan(_dataidx, len).CopyTo(MemoryMarshal.CreateSpan(ref block, 64));
                _dataidx += len;

                if (_dataidx == _data.Length)
                {
                    int spaceLeft = 64 - len;

                    if (spaceLeft > 0)
                    {
                        Unsafe.Add(ref block, len) = 0x80;
                        appended = true;

                        if (spaceLeft - 1 >= 8)
                        {
                            Unsafe.As<byte, ulong>(ref Unsafe.Add(ref block, 64 - 8)) = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(_bitsize) : _bitsize;
                            Complete = true;
                        }
                    }
                }
            }

            [MethodImpl(MethodImplOptions.AggressiveOptimization)]
            public void PrepareBlock(Span<byte> span)
            {
                Debug.Assert(span.Length == 64);

                int len = Math.Min(span.Length, Length() - _dataidx);

                if (len == 0)
                {
                    if (!appended)
                    {
                        span[0] = 0x80;
                        appended = true;
                    }

                    WriteBitsize(span);
                    Complete = true;
                    return;
                }

                _data.AsSpan(_dataidx, len).CopyTo(span);
                _dataidx += len;

                if (_dataidx == _data.Length)
                {
                    int spaceLeft = span.Length - len;

                    if (spaceLeft > 0)
                    {
                        span[len] = 0x80;
                        appended = true;

                        if (spaceLeft - 1 >= 8)
                        {
                            WriteBitsize(span);
                            Complete = true;
                        }
                    }
                }
            }

            private int Length()
            {
                return _data?.Length ?? 0;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private void WriteBitsize(Span<byte> span)
            {
                Unsafe.As<byte, ulong>(ref span[span.Length - 8]) = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(_bitsize) : _bitsize;
            }
        }
    }
}
