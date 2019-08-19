using System;
using System.Buffers;
using System.Numerics;
using System.Runtime.InteropServices;

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

        private static void ProcessBlockSHA512(Span<ulong> state, Span<ulong> schedule)
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
                var tmp1 = h + S1 + ch + SHA512TableK[i] + schedule[i];
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

        private static void InitScheduleSHA512(Span<ulong> schedule)
        {
            if (BitConverter.IsLittleEndian)
            {
                ReverseEndianess(schedule.Slice(0, 16));
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

    }
}
