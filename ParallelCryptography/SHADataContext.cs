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
        private ContextState state;

        public bool Complete { get => state == ContextState.Complete; } 

        public SHADataContext(byte[] data, AlgorithmWordSize wordSize = AlgorithmWordSize._32)
        {
            _data = data;

            int len = data is null ? 0 : data.Length;

            _dataLength = len;
            _bitsize = (ulong)len * 8;
            _dataidx = 0;

            _wordSize = wordSize;
            state = default;
        }

        public void PrepareBlock(byte* ptr, int len)
        {
            Debug.Assert(ptr != null);
            Debug.Assert(_wordSize switch { AlgorithmWordSize._32 => len == 64, AlgorithmWordSize._64 => len == 128 });
            Debug.Assert(state != ContextState.Complete);

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
                //We've reached the end of the data to process

                //Assert context state
                Debug.Assert(state == ContextState.Default);

                //Copy remaining data
                _data.AsSpan(_dataidx, lenRemain).CopyTo(new Span<byte>(ptr, len));

                //Append ending byte
                ptr[lenRemain++] = 0x80;
                state = ContextState.Appended; //Set state

                //Zero remaining memory
                Unsafe.InitBlockUnaligned(ptr + lenRemain, 0, (uint)(len - lenRemain));

                //If enough space is available at the end
                if (len - lenRemain >= ((int)_wordSize + 1) * 8)
                {
                    //add bit length to the end of the block, big endian
                    *(ulong*)(ptr + (len - sizeof(ulong))) = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(_bitsize) : _bitsize;
                    //Set completion state
                    state = ContextState.Complete;
                }
            }
            else
            {
                //Zero entire block
                Unsafe.InitBlock(ptr, 0, (uint)len);

                //If ending byte has not been appended yet
                if (state != ContextState.Appended)
                {
                    //Append it
                    ptr[0] = 0x80;
                }

                //add bit length to the end of the block, big endian
                *(ulong*)(ptr + (len - sizeof(ulong))) = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(_bitsize) : _bitsize;
                //Set completion flag
                state = ContextState.Complete;
            }
        }

        public enum AlgorithmWordSize : byte
        {
            _32 = 0,
            _64 = 1
        }

        private enum ContextState : byte
        {
            Default,
            Appended,
            Complete
        }
    }
}
