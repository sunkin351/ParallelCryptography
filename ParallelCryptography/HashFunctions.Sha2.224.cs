using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography
{
    public static partial class HashFunctions
    {
        public static byte[] SHA224(byte[] data)
        {
            SHADataContext ctx = new SHADataContext(data);

            Span<uint> state = stackalloc uint[8];

            state[0] = 0xc1059ed8;
            state[1] = 0x367cd507;
            state[2] = 0x3070dd17;
            state[3] = 0xf70e5939;
            state[4] = 0xffc00b31;
            state[5] = 0x68581511;
            state[6] = 0x64f98fa7;
            state[7] = 0xbefa4fa4;

            var scheduleMemory = MemoryPool.Rent(64);
            Span<uint> schedule = scheduleMemory.Memory.Span;

            Span<byte> dataPortion = MemoryMarshal.AsBytes(schedule.Slice(0, 16));

            Debug.Assert(dataPortion.Length == 64);

            do
            {
                ctx.PrepareBlock(dataPortion);
                InitScheduleSHA256(schedule);
                ProcessBlockSHA256(state, schedule);
            }
            while (!ctx.Complete);

            scheduleMemory.Dispose();

            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(state);
            }

            return MemoryMarshal.AsBytes(state.Slice(0, 7)).ToArray();
        }

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

            Span<Vector128<uint>> state = stackalloc Vector128<uint>[8];
            Span<bool> flags = stackalloc bool[4];
            SHADataContext[] contexts = new SHADataContext[4];

            contexts[0] = new SHADataContext(data1);
            contexts[1] = new SHADataContext(data2);
            contexts[2] = new SHADataContext(data3);
            contexts[3] = new SHADataContext(data4);

            var scheduleMemory = MemoryPool.Rent(64 * 4);
            Span<uint> schedule = scheduleMemory.Memory.Span;
            byte[][] hashes = AllocateHashs(4, sizeof(uint) * 7);

            state[0] = Vector128.Create(0xc1059ed8u);
            state[1] = Vector128.Create(0x367cd507u);
            state[2] = Vector128.Create(0x3070dd17u);
            state[3] = Vector128.Create(0xf70e5939u);
            state[4] = Vector128.Create(0xffc00b31u);
            state[5] = Vector128.Create(0x68581511u);
            state[6] = Vector128.Create(0x64f98fa7u);
            state[7] = Vector128.Create(0xbefa4fa4u);

            int concurrentHashes = 4, i;

            do
            {
                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (!ctx.Complete)
                    {
                        ctx.PrepareBlock(MemoryMarshal.AsBytes(schedule.Slice(i * 64, 16)));
                        InitScheduleSHA256(schedule.Slice(i * 64, 64));
                    }
                }

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
                Span<uint> block = schedule.Slice(0, 64);

                for (i = 0; i < 4; ++i)
                {
                    ref SHADataContext ctx = ref contexts[i];

                    if (ctx.Complete)
                    {
                        continue;
                    }

                    Span<uint> hash = new uint[8];

                    ExtractHashFromState(state, hash, i);

                    var dataBlock = MemoryMarshal.AsBytes(block.Slice(0, 16));

                    do
                    {
                        ctx.PrepareBlock(dataBlock);

                        InitScheduleSHA256(block);

                        ProcessBlockSHA256(hash, block);

                    } while (!ctx.Complete);

                    MemoryMarshal.AsBytes(hash.Slice(0, 7)).CopyTo(hashes[i]);
                }
            }

            scheduleMemory.Dispose();

            foreach (var hash in hashes)
            {
                Span<uint> hashSpan = MemoryMarshal.Cast<byte, uint>(hash);
                ReverseEndianess(hashSpan);
            }

            return hashes;
        }
    }
}
