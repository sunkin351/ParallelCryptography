using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography
{
    public static unsafe partial class HashFunctions
    {
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        [SkipLocalsInit]
        public static byte[] SHA384(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data, SHADataContext.AlgorithmWordSize._64);

            ulong* state = stackalloc ulong[8]
            {
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4
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
                byte[] hash = new byte[sizeof(ulong) * 6];

                fixed (byte* pHash = hash)
                {
                    ReverseEndianess(state, (ulong*)pHash, 6);
                }

                return hash;
            }

            return new Span<byte>(state, sizeof(ulong) * 6).ToArray();
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        [SkipLocalsInit]
        public static byte[][] SHA384Parallel(byte[] data1, byte[] data2)
        {
            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
            }

            if (!Sse2.IsSupported)
            {
                throw new NotSupportedException(SSE2_NotAvailable);
            }

            Vector128<ulong>* state = stackalloc Vector128<ulong>[8]
            {
                Vector128.Create(0xcbbb9d5dc1059ed8u),
                Vector128.Create(0x629a292a367cd507u),
                Vector128.Create(0x9159015a3070dd17u),
                Vector128.Create(0x152fecd8f70e5939u),
                Vector128.Create(0x67332667ffc00b31u),
                Vector128.Create(0x8eb44a8768581511u),
                Vector128.Create(0xdb0c2e0d64f98fa7u),
                Vector128.Create(0x47b5481dbefa4fa4u)
            };

            ulong* blocks = stackalloc ulong[16 * 2];

            Vector128<ulong>* schedule = stackalloc Vector128<ulong>[80];

            bool* flags = stackalloc bool[Vector128<ulong>.Count];
            Unsafe.InitBlock(flags, 0, 2);

            var contexts = new SHADataContext[2]
            {
                new SHADataContext(data1, SHADataContext.AlgorithmWordSize._64),
                new SHADataContext(data2, SHADataContext.AlgorithmWordSize._64)
            };

            byte[][] hashes = AllocateHashs(2, sizeof(ulong) * 6);

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
                            ExtractHashState_SHA384(state, (ulong*)hash, i);
                        }

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 1);

            if (concurrentHashes > 0)
            {
                ulong* scalarState = stackalloc ulong[8];

                for (i = 0; i < 2; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                    {
                        continue;
                    }

                    ExtractHashState_SHA512(state, scalarState, i);

                    do
                    {
                        ctx.PrepareBlock((byte*)schedule, sizeof(ulong) * 16);

                        InitScheduleSHA512((ulong*)schedule);

                        ProcessBlockSHA512(scalarState, (ulong*)schedule);

                    } while (!ctx.Complete);

                    new Span<byte>(scalarState, sizeof(ulong) * 6).CopyTo(hashes[i]);
                }
            }

            foreach (var hash in hashes)
            {
                fixed (byte* phash = hash)
                    ReverseEndianess((ulong*)phash, 6);
            }

            return hashes;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        [SkipLocalsInit]
        public static byte[][] SHA384Parallel(byte[] data1, byte[] data2, byte[] data3, byte[] data4)
        {
            if (!BitConverter.IsLittleEndian)
            {
                throw new NotSupportedException(BigEndian_NotSupported);
            }

            if (!Avx2.IsSupported)
            {
                throw new NotSupportedException(AVX2_NotAvailable);
            }

            Vector256<ulong>* state = stackalloc Vector256<ulong>[8]
            {
                Vector256.Create(0xcbbb9d5dc1059ed8u),
                Vector256.Create(0x629a292a367cd507u),
                Vector256.Create(0x9159015a3070dd17u),
                Vector256.Create(0x152fecd8f70e5939u),
                Vector256.Create(0x67332667ffc00b31u),
                Vector256.Create(0x8eb44a8768581511u),
                Vector256.Create(0xdb0c2e0d64f98fa7u),
                Vector256.Create(0x47b5481dbefa4fa4u)
            };

            ulong* blocks = stackalloc ulong[16 * 4];

            Vector256<ulong>* schedule = stackalloc Vector256<ulong>[80];

            bool* flags = stackalloc bool[4];
            Unsafe.InitBlock(flags, 0, 4);

            SHADataContext[] contexts = new SHADataContext[4]
            {
                new SHADataContext(data1, SHADataContext.AlgorithmWordSize._64),
                new SHADataContext(data2, SHADataContext.AlgorithmWordSize._64),
                new SHADataContext(data3, SHADataContext.AlgorithmWordSize._64),
                new SHADataContext(data4, SHADataContext.AlgorithmWordSize._64)
            };

            byte[][] hashes = AllocateHashs(4, sizeof(ulong) * 6);

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
                            ExtractHashState_SHA384(state, (ulong*)hash, i);
                        }

                        concurrentHashes -= 1;
                    }
                }
            }
            while (concurrentHashes > 2);

            if (concurrentHashes > 0)
            {
                ulong* scalarState = stackalloc ulong[8];

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                    {
                        continue;
                    }

                    ExtractHashState_SHA512(state, scalarState, i);

                    do
                    {
                        ctx.PrepareBlock((byte*)schedule, sizeof(ulong) * 16);

                        InitScheduleSHA512((ulong*)schedule);

                        ProcessBlockSHA512(scalarState, (ulong*)schedule);

                    } while (!ctx.Complete);

                    new Span<byte>(scalarState, sizeof(ulong) * 6).CopyTo(hashes[i]);
                }
            }

            foreach (var hash in hashes)
            {
                fixed (byte* phash = hash)
                    ReverseEndianess((ulong*)phash, 6);
            }

            return hashes;
        }

        private static void ExtractHashState_SHA384(Vector128<ulong>* state, ulong* hash, int hashIdx)
        {
            ExtractHashState(state, hash, hashIdx, 6);
        }

        private static void ExtractHashState_SHA384(Vector256<ulong>* state, ulong* hash, int hashIdx)
        {
            ExtractHashState(state, hash, hashIdx, 6);
        }
    }
}
