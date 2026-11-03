using System;
using System.Reflection;

namespace DemoTarget
{
    /// <summary>
    /// Reflective assembly loader.
    ///
    /// Demonstrates the Assembly.Load(byte[]) pattern used by .NET malware to
    /// load second-stage payloads that never touch disk. The FerrIL asmdump
    /// profiler hooks this call, copies the byte[] argument, verifies the MZ
    /// header, and dumps it to disk for analysis.
    /// </summary>
    internal static class AssemblyLoader
    {
        /// <summary>
        /// Load an assembly from raw bytes using Assembly.Load(byte[]).
        /// This is the exact API that asmdump targets.
        /// </summary>
        public static Assembly LoadFromBytes(byte[] assemblyBytes)
        {
            Console.WriteLine("[Loader] Loading assembly from {0} bytes via Assembly.Load(byte[])",
                assemblyBytes.Length);

            // Verify MZ header (same check asmdump performs)
            if (assemblyBytes.Length >= 2)
            {
                Console.WriteLine("[Loader] Header bytes: 0x{0:X2} 0x{1:X2} ({2})",
                    assemblyBytes[0], assemblyBytes[1],
                    (assemblyBytes[0] == 0x4D && assemblyBytes[1] == 0x5A) ? "MZ ✓" : "not MZ");
            }

            // This is the call that asmdump intercepts via FunctionEnter2.
            // The profiler reads arg[0] (the byte[] for this static method),
            // confirms it is an SZArray of bytes, copies the buffer, checks
            // for the MZ header, and writes it to dump-XXXX.dll.
            Assembly loaded = Assembly.Load(assemblyBytes);

            Console.WriteLine("[Loader] Successfully loaded: {0}", loaded.FullName);
            return loaded;
        }
    }
}
