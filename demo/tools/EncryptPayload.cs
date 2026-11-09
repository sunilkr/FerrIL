using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Build-time utility: encrypts DemoPayload.dll into payload.bin using the
/// same AES key/IV that EmbeddedPayload.DecryptPayload() expects at runtime.
///
/// Usage: EncryptPayload.exe <input.dll> <output.bin>
/// </summary>
class EncryptPayload
{
    // Must match EmbeddedPayload.PayloadKey / PayloadIV
    private static readonly byte[] Key = Encoding.ASCII.GetBytes("PayloadKey!16byt");
    private static readonly byte[] IV  = Encoding.ASCII.GetBytes("PayloadIVec16byt");

    static int Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.WriteLine("Usage: EncryptPayload.exe <input.dll> <output.bin>");
            return 1;
        }

        string inputPath  = args[0];
        string outputPath = args[1];

        if (!File.Exists(inputPath))
        {
            Console.WriteLine("ERROR: Input file not found: {0}", inputPath);
            return 1;
        }

        byte[] rawBytes = File.ReadAllBytes(inputPath);
        Console.WriteLine("  Input:  {0} ({1} bytes)", inputPath, rawBytes.Length);

        using (var aes = new AesCryptoServiceProvider())
        {
            aes.Key = Key;
            aes.IV = IV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var encryptor = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(rawBytes, 0, rawBytes.Length);
                }
                byte[] encrypted = ms.ToArray();
                File.WriteAllBytes(outputPath, encrypted);
                Console.WriteLine("  Output: {0} ({1} bytes)", outputPath, encrypted.Length);
            }
        }

        return 0;
    }
}
