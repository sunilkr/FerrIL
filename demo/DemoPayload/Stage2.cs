using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DemoPayload
{
    /// <summary>
    /// Second-stage payload — loaded reflectively via Assembly.Load(byte[]).
    ///
    /// This assembly is never on disk at runtime: it is AES-encrypted inside
    /// the loader (DemoTarget), decrypted in memory, and passed to
    /// Assembly.Load(byte[]). The FerrIL asmdump profiler intercepts that
    /// call and dumps the bytes so analysts can recover this DLL.
    ///
    /// Once loaded, the loader invokes Stage2.Execute(host, port) by
    /// reflection. Stage2 then:
    ///   1. Encrypts a beacon message with AES  (fntrace can capture plaintext)
    ///   2. Connects to the server over TLS with a pinned certificate
    ///      (ssl_unpin bypasses the pin so MITM can inspect the traffic)
    ///   3. Sends the encrypted beacon over the pinned channel
    /// </summary>
    public class Stage2
    {
        /// <summary>
        /// Entry point called by the loader via reflection.
        /// </summary>
        public static string Execute(string host, int port, bool noSslVerify)
        {
            Console.WriteLine();
            Console.WriteLine("[Stage2] Running from reflectively loaded assembly");
            Console.WriteLine("[Stage2] PID={0} | Time={1}",
                System.Diagnostics.Process.GetCurrentProcess().Id,
                DateTime.UtcNow.ToString("o"));
            Console.WriteLine("[Stage2] Target server: {0}:{1}", host, port);
            Console.WriteLine();

            // ── Encrypted communication ──────────────────────────────
            string beacon = string.Format("BEACON|{0}|{1}",
                Guid.NewGuid().ToString("N").Substring(0, 8),
                DateTime.UtcNow.ToString("o"));

            Console.WriteLine("[Stage2] === Encrypted Communication ===");
            Console.WriteLine("[Stage2] Plaintext beacon: \"{0}\"", beacon);

            byte[] encrypted = CryptoChannel.Encrypt(beacon);
            Console.WriteLine("[Stage2] Ciphertext (hex): {0}", BitConverter.ToString(encrypted));

            // Verify round-trip
            string decrypted = CryptoChannel.Decrypt(encrypted);
            Console.WriteLine("[Stage2] Round-trip check: \"{0}\"", decrypted);
            Console.WriteLine();

            // ── SSL-pinned connection ─────────────────────────────────
            Console.WriteLine("[Stage2] === SSL Certificate Pinning ===");
            if (noSslVerify)
                Console.WriteLine("[Stage2] Certificate validation DISABLED (--no-ssl)");
            CertPinning.SendMessage(host, port, encrypted, noSslVerify);

            return string.Format("Stage2 complete — sent {0} encrypted bytes to {1}:{2}",
                encrypted.Length, host, port);
        }
    }

    /// <summary>
    /// SSL certificate pinning via SslStream.
    ///
    /// The custom RemoteCertificateValidationCallback checks the server
    /// certificate thumbprint against a pinned value. The FerrIL ssl_unpin
    /// profiler replaces SslStream.userCertValidationCallbackWrapper with
    /// "ldc.i4.1; ret" (return true) to bypass this check, enabling MITM
    /// inspection of TLS traffic.
    /// </summary>
    internal static class CertPinning
    {
        // Pinned certificate thumbprint (SHA-1).
        // Any server whose cert doesn't match this is rejected — unless
        // ssl_unpin patches the validation wrapper to always return true.
        private const string PinnedThumbprint = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";

        /// <summary>
        /// Connect to a TLS server with certificate pinning.
        /// When <paramref name="noSslVerify"/> is true, all certificates are accepted.
        /// </summary>
        public static SslStream Connect(string host, int port, bool noSslVerify = false)
        {
            Console.WriteLine("[CertPin] Connecting to {0}:{1} with certificate {2}...",
                host, port, noSslVerify ? "validation disabled" : "pinning");

            var client = new TcpClient(host, port);
            var sslStream = new SslStream(
                client.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: noSslVerify
                    ? (RemoteCertificateValidationCallback)AcceptAnyCertificate
                    : ValidateServerCertificate);

            try
            {
                sslStream.AuthenticateAsClient(host, null, SslProtocols.Tls12, checkCertificateRevocation: false);
                Console.WriteLine("[CertPin] TLS handshake succeeded — certificate accepted");
            }
            catch (AuthenticationException ex)
            {
                Console.WriteLine("[CertPin] TLS handshake FAILED: {0}", ex.Message);
                client.Close();
                throw;
            }

            return sslStream;
        }

        /// <summary>
        /// Custom certificate validation callback.
        /// ssl_unpin targets userCertValidationCallbackWrapper which calls this.
        /// Replacing the wrapper with "return true" bypasses this pinning check.
        /// </summary>
        private static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (certificate == null)
            {
                Console.WriteLine("[CertPin] No certificate presented — rejecting");
                return false;
            }

            string thumbprint = certificate.GetCertHashString();
            Console.WriteLine("[CertPin] Server certificate thumbprint: {0}", thumbprint);

            if (!string.Equals(thumbprint, PinnedThumbprint, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("[CertPin] Thumbprint does NOT match pinned value — rejecting");
                return false;
            }

            Console.WriteLine("[CertPin] Thumbprint matches pinned value — accepting");
            return true;
        }

        /// <summary>
        /// Permissive certificate callback — accepts any certificate.
        /// Used when --no-ssl is passed to skip validation entirely.
        /// </summary>
        private static bool AcceptAnyCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("[CertPin] Certificate validation SKIPPED (--no-ssl) — accepting");
            return true;
        }

        /// <summary>
        /// Connect, send a length-prefixed encrypted message, then close.
        /// </summary>
        public static void SendMessage(string host, int port, byte[] encryptedMessage, bool noSslVerify = false)
        {
            try
            {
                using (var ssl = Connect(host, port, noSslVerify))
                {
                    Console.WriteLine("[CertPin] Sending {0} encrypted bytes over pinned TLS channel",
                        encryptedMessage.Length);

                    // Write length-prefixed message
                    byte[] lenPrefix = BitConverter.GetBytes(encryptedMessage.Length);
                    ssl.Write(lenPrefix, 0, lenPrefix.Length);
                    ssl.Write(encryptedMessage, 0, encryptedMessage.Length);
                    ssl.Flush();

                    Console.WriteLine("[CertPin] Message sent successfully");

                    // Read length-prefixed ACK response
                    byte[] respLenBuf = new byte[4];
                    int read = ssl.Read(respLenBuf, 0, 4);
                    if (read == 4)
                    {
                        int respLen = BitConverter.ToInt32(respLenBuf, 0);
                        if (respLen > 0 && respLen < 65536)
                        {
                            byte[] respBuf = new byte[respLen];
                            int totalRead = 0;
                            while (totalRead < respLen)
                            {
                                int n = ssl.Read(respBuf, totalRead, respLen - totalRead);
                                if (n <= 0) break;
                                totalRead += n;
                            }
                            string response = System.Text.Encoding.UTF8.GetString(respBuf, 0, totalRead);
                            Console.WriteLine("[CertPin] Server response: {0}", response);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[CertPin] Connection failed (expected without ssl_unpin): {0}",
                    ex.GetBaseException().Message);
            }
        }
    }

    /// <summary>
    /// AES-encrypted communication channel.
    ///
    /// Encrypts C2 messages so network capture reveals no IOCs. The FerrIL
    /// fntrace profiler can intercept method arguments (the plaintext before
    /// encryption, or after decryption) to recover cleartext.
    /// </summary>
    internal static class CryptoChannel
    {
        private static readonly byte[] Key = Encoding.ASCII.GetBytes("DemoAesKey!16byt");  // AES-128
        private static readonly byte[] IV  = Encoding.ASCII.GetBytes("InitVector!16byt");

        /// <summary>
        /// Encrypt a plaintext string. fntrace captures the plaintext arg.
        /// </summary>
        public static byte[] Encrypt(string plaintext)
        {
            Console.WriteLine("[Crypto] Encrypting message ({0} chars)", plaintext.Length);

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
                        byte[] data = Encoding.UTF8.GetBytes(plaintext);
                        cs.Write(data, 0, data.Length);
                    }
                    byte[] ciphertext = ms.ToArray();
                    Console.WriteLine("[Crypto] Ciphertext: {0} bytes", ciphertext.Length);
                    return ciphertext;
                }
            }
        }

        /// <summary>
        /// Decrypt ciphertext. fntrace captures the return value.
        /// </summary>
        public static string Decrypt(byte[] ciphertext)
        {
            Console.WriteLine("[Crypto] Decrypting {0} bytes", ciphertext.Length);

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = Key;
                aes.IV = IV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                using (var ms = new MemoryStream(ciphertext))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var reader = new StreamReader(cs, Encoding.UTF8))
                {
                    string plaintext = reader.ReadToEnd();
                    Console.WriteLine("[Crypto] Decrypted: {0} chars", plaintext.Length);
                    return plaintext;
                }
            }
        }
    }
}
