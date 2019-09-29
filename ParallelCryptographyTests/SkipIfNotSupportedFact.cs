using Xunit;

namespace ParallelCryptography.Tests
{
    public abstract class SkipIfNotSupportedFactAttribute : FactAttribute
    {
        public SkipIfNotSupportedFactAttribute()
        {
            if (!IsSupported)
            {
                Skip = $"{InstructionSetName} is not supported on this platform.";
            }
        }

        protected abstract bool IsSupported { get; }
        protected abstract string InstructionSetName { get; }
    }
}
