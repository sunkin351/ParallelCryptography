using System;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography.Tests
{
    public class Avx2IsSupportedFactAttribute : SkipIfNotSupportedFactAttribute
    {
        protected override bool IsSupported => Avx2.IsSupported;

        protected override string InstructionSetName => nameof(Avx2);
    }
}
