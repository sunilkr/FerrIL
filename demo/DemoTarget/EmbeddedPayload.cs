using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DemoTarget
{
    /// <summary>
    /// Holds the embedded, AES-encrypted payload assembly.
    ///
    /// In real malware, the second-stage DLL is embedded as an encrypted blob
    /// in the binary's resources or a static byte array. At runtime, it is
    /// decrypted and passed to Assembly.Load(byte[]).
    ///
    /// This class loads DemoPayload.dll from disk (expected next to the exe),
    /// encrypts it with AES at runtime to simulate the pattern, then decrypts
    /// and loads. If the DLL is pre-encrypted (payload.bin), it loads that directly.
    ///
    /// For a true embedded demo, run build_payload.bat first, which compiles
    /// DemoPayload.dll and produces EmbeddedBlob.cs with a hardcoded byte array.
    /// </summary>
    internal static class EmbeddedPayload
    {
        // Same key/IV as CryptoChannel — in practice, payload key might differ
        private static readonly byte[] PayloadKey = Encoding.ASCII.GetBytes("PayloadKey!16byt");
        private static readonly byte[] PayloadIV  = Encoding.ASCII.GetBytes("PayloadIVec16byt");

        /// <summary>
        /// Get the decrypted payload assembly bytes, ready for Assembly.Load().
        /// Tries multiple sources in order:
        ///   1. Pre-encrypted payload.bin (most realistic)
        ///   2. Raw DemoPayload.dll on disk (encrypts + decrypts at runtime)
        /// </summary>
        public static byte[] GetPayloadBytes()
        {
            Console.WriteLine("[Payload] Resolving embedded payload...");

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            // Source 1: pre-encrypted blob
            string encPath = Path.Combine(baseDir, "payload.bin");
            if (File.Exists(encPath))
            {
                Console.WriteLine("[Payload] Found pre-encrypted payload: {0}", encPath);
                byte[] encBlob = File.ReadAllBytes(encPath);
                Console.WriteLine("[Payload] Encrypted blob: {0} bytes", encBlob.Length);
                return DecryptPayload(encBlob);
            }

            // Source 2: raw DLL — encrypt then decrypt (demonstrates the full cycle)
            string dllPath = Path.Combine(baseDir, "DemoPayload.dll");
            if (File.Exists(dllPath))
            {
                Console.WriteLine("[Payload] Found raw DLL: {0}", dllPath);
                byte[] rawBytes = File.ReadAllBytes(dllPath);
                Console.WriteLine("[Payload] Raw DLL: {0} bytes (MZ header: 0x{1:X2} 0x{2:X2})",
                    rawBytes.Length, rawBytes[0], rawBytes[1]);

                // Encrypt (simulating the build/packing step)
                byte[] encrypted = EncryptPayload(rawBytes);
                Console.WriteLine("[Payload] Encrypted to {0} bytes", encrypted.Length);

                // Decrypt (simulating the runtime unpacking step)
                byte[] decrypted = DecryptPayload(encrypted);
                Console.WriteLine("[Payload] Decrypted back to {0} bytes", decrypted.Length);

                return decrypted;
            }

            Console.WriteLine("[Payload] ERROR: No payload found. Build DemoPayload first.");
            Console.WriteLine("[Payload] Expected at: {0}", dllPath);
            return null;
        }

        public static byte[] EncryptPayload(byte[] rawBytes)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = PayloadKey;
                aes.IV = PayloadIV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(rawBytes, 0, rawBytes.Length);
                    }
                    return ms.ToArray();
                }
            }
        }

        public static byte[] DecryptPayload(byte[] encryptedBytes)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = PayloadKey;
                aes.IV = PayloadIV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                using (var ms = new MemoryStream(encryptedBytes))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var result = new MemoryStream())
                {
                    cs.CopyTo(result);
                    return result.ToArray();
                }
            }
        }
    }
}
