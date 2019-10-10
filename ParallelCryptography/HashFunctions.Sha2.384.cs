using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography
{
    public static partial class HashFunctions
    {
        public static byte[] SHA384(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            Span<ulong> state = stackalloc ulong[8]
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

            Span<ulong> schedule = stackalloc ulong[80];
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

            return MemoryMarshal.AsBytes(state.Slice(0, 6)).ToArray();
        }

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

            Span<Vector128<ulong>> state = stackalloc Vector128<ulong>[8]
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

            Span<ulong> blocks = stackalloc ulong[16 * 2];

            Span<Vector128<ulong>> schedule = stackalloc Vector128<ulong>[80];

            Span<bool> flags = stackalloc bool[2];

            SHADataContext[] contexts = new SHADataContext[2];

            contexts[0] = new SHADataContext(data1);
            contexts[1] = new SHADataContext(data2);

            byte[][] hashes = AllocateHashs(2, sizeof(ulong) * 6);

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
                Span<ulong> scalarSchedule = MemoryMarshal.Cast<Vector128<ulong>, ulong>(schedule).Slice(0, 80);
                Span<byte> dataBlock = MemoryMarshal.AsBytes(scalarSchedule.Slice(0, 16));

                Span<ulong> scalarState = new ulong[8];

                for (i = 0; i < 2; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                    {
                        continue;
                    }

                    ExtractHashFromState(state, scalarState, i);

                    do
                    {
                        ctx.PrepareBlock(dataBlock);

                        InitScheduleSHA512(scalarSchedule);

                        ProcessBlockSHA512(scalarState, scalarSchedule);

                    } while (!ctx.Complete);

                    MemoryMarshal.AsBytes(scalarState.Slice(0, 6)).CopyTo(hashes[i]);
                }
            }

            foreach (var hash in hashes)
            {
                Span<ulong> hashSpan = MemoryMarshal.Cast<byte, ulong>(hash);
                ReverseEndianess(hashSpan);
            }

            return hashes;
        }

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

            Span<Vector256<ulong>> state = stackalloc Vector256<ulong>[8]
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

            Span<ulong> blocks = stackalloc ulong[16 * 4];
            Span<Vector256<ulong>> schedule = stackalloc Vector256<ulong>[80];

            Span<bool> flags = stackalloc bool[4];
            SHADataContext[] contexts = new SHADataContext[4];

            contexts[0] = new SHADataContext(data1);
            contexts[1] = new SHADataContext(data2);
            contexts[2] = new SHADataContext(data3);
            contexts[3] = new SHADataContext(data4);

            byte[][] hashes = AllocateHashs(4, sizeof(ulong) * 6);

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
                Span<ulong> scalarSchedule = MemoryMarshal.Cast<Vector256<ulong>, ulong>(schedule).Slice(0, 80);
                var dataBlock = MemoryMarshal.AsBytes(scalarSchedule.Slice(0, 16));

                Span<ulong> scalarState = new ulong[8];

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                    {
                        continue;
                    }

                    ExtractHashFromState(state, scalarState, i);

                    do
                    {
                        ctx.PrepareBlock(dataBlock);

                        InitScheduleSHA512(scalarSchedule);

                        ProcessBlockSHA512(scalarState, scalarSchedule);

                    } while (!ctx.Complete);

                    MemoryMarshal.AsBytes(scalarState.Slice(0, 6)).CopyTo(hashes[i]);
                }
            }

            foreach (var hash in hashes)
            {
                Span<ulong> hashSpan = MemoryMarshal.Cast<byte, ulong>(hash);
                ReverseEndianess(hashSpan);
            }

            return hashes;
        }
    }
}
