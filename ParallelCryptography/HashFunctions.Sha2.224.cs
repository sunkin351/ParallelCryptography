using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography
{
    public static unsafe partial class HashFunctions
    {
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static byte[] SHA224(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            uint* state = stackalloc uint[8]
            {
                0xc1059ed8,
                0x367cd507,
                0x3070dd17,
                0xf70e5939,
                0xffc00b31,
                0x68581511,
                0x64f98fa7,
                0xbefa4fa4
            };

            uint* schedule = stackalloc uint[64];

            do
            {
                ctx.PrepareBlock((byte*)schedule, sizeof(uint) * 16);
                InitScheduleSHA256(schedule);
                ProcessBlockSHA256(state, schedule);
            }
            while (!ctx.Complete);

            if (BitConverter.IsLittleEndian)
            {
                byte[] hash = new byte[sizeof(uint) * 7];

                fixed (byte* phash = hash)
                {
                    ReverseEndianess(state, (uint*)phash, 7);
                }

                return hash;
            }
            else
            {
                return new Span<byte>(state, sizeof(uint) * 7).ToArray();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static byte[][] SHA224Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException(SSE2_NotAvailable);
            }

            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
            }

            Vector128<uint>* state = stackalloc Vector128<uint>[8]
            {
                Vector128.Create(0xc1059ed8u),
                Vector128.Create(0x367cd507u),
                Vector128.Create(0x3070dd17u),
                Vector128.Create(0xf70e5939u),
                Vector128.Create(0xffc00b31u),
                Vector128.Create(0x68581511u),
                Vector128.Create(0x64f98fa7u),
                Vector128.Create(0xbefa4fa4u)
            };

            bool* flags = stackalloc bool[4];
            
            SHADataContext[] contexts = new SHADataContext[4]
            {
                new SHADataContext(data1),
                new SHADataContext(data2),
                new SHADataContext(data3),
                new SHADataContext(data4)
            };

            uint* blocks = stackalloc uint[16 * 4];
            
            Vector128<uint>* schedule = stackalloc Vector128<uint>[64];

            byte[][] hashes = AllocateHashs(4, sizeof(uint) * 7);

            int concurrentHashes = 4, i;

            do
            {
                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock((byte*)(blocks + i * 16), sizeof(uint) * 16);
                    }
                }

                InitScheduleSHA256Parallel(schedule, blocks);

                ProcessBlocksParallelSHA256(state, schedule);

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (flags[i] != ctx.Complete)
                    {
                        flags[i] = ctx.Complete;

                        fixed (byte* pHash = hashes[i])
                            ExtractHashState_SHA224(state, (uint*)pHash, i);

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 2);

            if (concurrentHashes > 0)
            {
                uint* scalarState = stackalloc uint[8];

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                    {
                        continue;
                    }

                    ExtractHashState_SHA256(state, scalarState, i);

                    do
                    {
                        ctx.PrepareBlock((byte*)schedule, sizeof(uint) * 16);

                        InitScheduleSHA256((uint*)schedule);

                        ProcessBlockSHA256(scalarState, (uint*)schedule);

                    } while (!ctx.Complete);

                    new Span<byte>(scalarState, sizeof(uint) * 7).CopyTo(hashes[i]);
                }
            }

            foreach (var hash in hashes)
            {
                fixed (byte* phash = hash)
                    ReverseEndianess((uint*)phash, 7);
            }

            return hashes;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static void ExtractHashState_SHA224(Vector128<uint>* state, uint* hash, int hashIdx)
        {
            Debug.Assert((uint)hashIdx < (uint)Vector128<uint>.Count);

            uint* stateScalar = (uint*)state;

            for (int i = 0; i < 7; ++i)
            {
                hash[i] = stateScalar[Vector128<uint>.Count * i + hashIdx];
            }
        }
    }
}
