using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ParallelCryptography
{
    [StructLayout(LayoutKind.Auto)]
    internal unsafe struct SHADataContext
    {
        private readonly byte[] _data;
        private readonly ulong _bitsize;
        private readonly int _dataLength;
        private int _dataidx;
        private readonly AlgorithmWordSize _wordSize;
        private bool appended;

        public bool Complete { get; private set; } 

        public SHADataContext(byte[] data, AlgorithmWordSize wordSize = AlgorithmWordSize._32)
        {
            _data = data;

            int len = data == null ? 0 : data.Length;

            _dataLength = len;
            _bitsize = (ulong)len * 8;
            _dataidx = 0;

            _wordSize = wordSize;

            appended = false;
            Complete = false;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public void PrepareBlock(byte* ptr, int len)
        {
            Debug.Assert(ptr != null);
            Debug.Assert(_wordSize switch { AlgorithmWordSize._32 => len == 64, AlgorithmWordSize._64 => len == 128 });
            Debug.Assert(!this.Complete);

            //Data remaining
            int lenRemain = _dataLength - _dataidx;

            if (lenRemain >= len)
            {
                //Straight copy if there's more data than can fit
                _data.AsSpan(_dataidx, len).CopyTo(new Span<byte>(ptr, len));
                _dataidx += len;
            }
            else if (lenRemain > 0)
            {
                Debug.Assert(!appended);

                _data.AsSpan(_dataidx, lenRemain).CopyTo(new Span<byte>(ptr, len));

                ptr[lenRemain++] = 0x80;
                appended = true;

                Unsafe.InitBlockUnaligned(ptr + lenRemain, 0, (uint)(len - lenRemain));

                if (len - lenRemain >= ((int)_wordSize + 1) * 8)
                {
                    *(ulong*)(ptr + (len - sizeof(ulong))) = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(_bitsize) : _bitsize;
                    Complete = true;
                }
            }
            else
            {
                Unsafe.InitBlock(ptr, 0, (uint)len);

                if (!appended)
                {
                    ptr[0] = 0x80;
                }

                *(ulong*)(ptr + (len - sizeof(ulong))) = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(_bitsize) : _bitsize;
                Complete = true;
            }
        }

        public enum AlgorithmWordSize : byte
        {
            _32 = 0,
            _64 = 1
        }
    }
}
