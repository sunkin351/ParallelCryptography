﻿using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography
{
    public static partial class HashFunctions
    {
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static byte[] SHA224(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            Span<uint> state = stackalloc uint[8]
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

            Span<uint> schedule = stackalloc uint[64];

            Span<byte> dataPortion = MemoryMarshal.AsBytes(schedule.Slice(0, 16));

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

            return MemoryMarshal.AsBytes(state.Slice(0, 7)).ToArray();
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

            Span<Vector128<uint>> state = stackalloc Vector128<uint>[8]
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

            Span<bool> flags = stackalloc bool[4];
            SHADataContext[] contexts = new SHADataContext[4]
            {
                new SHADataContext(data1),
                new SHADataContext(data2),
                new SHADataContext(data3),
                new SHADataContext(data4)
            };

            Span<uint> blocks = stackalloc uint[16 * 4];
            Span<Vector128<uint>> schedule = stackalloc Vector128<uint>[64];
            byte[][] hashes = AllocateHashs(4, sizeof(uint) * 7);

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

                InitScheduleSHA256Parallel(schedule, blocks);

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
                var dataBlock = MemoryMarshal.AsBytes(blocks.Slice(0, 16));

                Span<uint> scalarState = new uint[8];

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

                        InitScheduleSHA256(blocks);

                        ProcessBlockSHA256(scalarState, blocks);

                    } while (!ctx.Complete);

                    MemoryMarshal.AsBytes(scalarState.Slice(0, 7)).CopyTo(hashes[i]);
                }
            }

            foreach (var hash in hashes)
            {
                Span<uint> hashSpan = MemoryMarshal.Cast<byte, uint>(hash);
                ReverseEndianess(hashSpan);
            }

            return hashes;
        }
    }
}
