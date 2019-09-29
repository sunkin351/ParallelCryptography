using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.Intrinsics.X86;

namespace ParallelCryptography.Tests
{
    public class Sse2IsSupportedFactAttribute : SkipIfNotSupportedFactAttribute
    {
        protected override bool IsSupported => Sse2.IsSupported;

        protected override string InstructionSetName => nameof(Sse2);
    }
}
