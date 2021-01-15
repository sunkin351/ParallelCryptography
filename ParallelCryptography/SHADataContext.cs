using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ParallelCryptography
{
    [StructLayout(LayoutKind.Auto)]
    internal struct SHADataContext
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

        public unsafe void PrepareBlock(byte* ptr, int len)
        {
            PrepareBlock(new Span<byte>(ptr, len));
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public void PrepareBlock(Span<byte> span)
        {
            Debug.Assert(_wordSize switch { AlgorithmWordSize._32 => span.Length == 64, AlgorithmWordSize._64 => span.Length == 128 });
            Debug.Assert(!this.Complete);

            //Data remaining
            int lenRemain = _dataLength - _dataidx;

            if (lenRemain >= span.Length)
            {
                //Straight copy if there's more data than can fit
                _data.AsSpan(_dataidx, span.Length).CopyTo(span);
                _dataidx += span.Length;
            }
            else if (lenRemain > 0)
            {
                Debug.Assert(!appended);

                _data.AsSpan(_dataidx, lenRemain).CopyTo(span);

                span[lenRemain++] = 0x80;
                appended = true;

                span.Slice(lenRemain).Clear();

                if (span.Length - lenRemain >= ((int)_wordSize + 1) * 8)
                {
                    BinaryPrimitives.WriteUInt64BigEndian(span.Slice(span.Length - sizeof(ulong)), _bitsize);
                    Complete = true;
                }
            }
            else
            {
                span.Clear();

                if (!appended)
                {
                    span[0] = 0x80;
                }

                BinaryPrimitives.WriteUInt64BigEndian(span.Slice(span.Length - sizeof(ulong)), _bitsize);
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
