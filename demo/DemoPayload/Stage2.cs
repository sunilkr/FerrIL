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
    /// Once loaded, the loader invokes Stage2.Execute(host, port, noSslVerify)
    /// by reflection. Stage2 then:
    ///   1. Connects to the server over TLS with a pinned certificate
    ///      (ssl_unpin bypasses the pin so MITM can inspect the traffic)
    ///   2. Encrypts a beacon message with AES  (fntrace can capture plaintext)
    ///   3. Sends the encrypted beacon over the pinned channel
    ///   4. Reads the server's encrypted ACK, decrypts it, and verifies it
    ///      echoes the beacon (server authentication — proves the server
    ///      holds the shared key and understood the protocol)
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

            // ── Step 1: SSL certificate verification ─────────────────
            Console.WriteLine("[Stage2] === Step 1: SSL Certificate Verification ===");
            if (noSslVerify)
                Console.WriteLine("[Stage2] Certificate validation DISABLED (--no-ssl)");

            SslStream ssl;
            try
            {
                ssl = ServerChannel.Connect(host, port, noSslVerify);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[Stage2] Connection failed (expected without ssl_unpin): {0}",
                    ex.GetBaseException().Message);
                return string.Format("Stage2 failed — could not connect to {0}:{1}", host, port);
            }
            Console.WriteLine();

            // ── Step 2: Encrypt and send beacon ──────────────────────
            Console.WriteLine("[Stage2] === Step 2: Send Encrypted Beacon ===");

            string beacon = string.Format("BEACON|{0}|{1}",
                Guid.NewGuid().ToString("N").Substring(0, 8),
                DateTime.UtcNow.ToString("o"));

            byte[] encrypted = CryptoChannel.Encrypt(beacon);
            Console.WriteLine("[Stage2] Encrypted beacon: {0} bytes", encrypted.Length);

            try
            {
                ServerChannel.SendBeacon(ssl, encrypted);
            }
            catch (Exception ex)
            {
                ssl.Dispose();
                Console.WriteLine("[Stage2] Send failed: {0}", ex.GetBaseException().Message);
                return string.Format("Stage2 failed — send error to {0}:{1}", host, port);
            }
            Console.WriteLine();

            // ── Step 3: Verify server response (server authentication) ──
            Console.WriteLine("[Stage2] === Step 3: Verify Server Response ===");

            try
            {
                bool verified = ServerChannel.VerifyServerAck(ssl, beacon);
                if (verified)
                    Console.WriteLine("[Stage2] Server authenticated — ACK matches beacon");
                else
                    Console.WriteLine("[Stage2] Server authentication FAILED — ACK mismatch");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[Stage2] Server verification failed: {0}",
                    ex.GetBaseException().Message);
            }
            finally
            {
                ssl.Dispose();
            }

            return string.Format("Stage2 complete — sent {0} encrypted bytes to {1}:{2}",
                encrypted.Length, host, port);
        }
    }

    /// <summary>
    /// TLS channel with certificate pinning and server authentication.
    ///
    /// Connection lifecycle:
    ///   1. Connect()         — TCP + TLS handshake with cert pinning
    ///   2. SendBeacon()      — send length-prefixed encrypted beacon
    ///   3. VerifyServerAck() — read encrypted ACK, decrypt, verify it
    ///                          echoes the beacon (server authentication)
    ///
    /// The custom RemoteCertificateValidationCallback checks the server
    /// certificate thumbprint against a pinned value. The FerrIL ssl_unpin
    /// profiler replaces SslStream.userCertValidationCallbackWrapper with
    /// "ldc.i4.1; ret" (return true) to bypass this check, enabling MITM
    /// inspection of TLS traffic.
    /// </summary>
    internal static class ServerChannel
    {
        // Pinned certificate thumbprint (SHA-1).
        // Any server whose cert doesn't match this is rejected — unless
        // ssl_unpin patches the validation wrapper to always return true.
        private const string PinnedThumbprint = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";

        // Expected ACK wrapper from the server: ACK{<beacon>}
        private const string AckPrefix = "ACK{";
        private const char   AckSuffix = '}';

        // ── Step 1: TLS Connect ──────────────────────────────────────

        /// <summary>
        /// Open a TLS connection to the server with certificate pinning.
        /// When <paramref name="noSslVerify"/> is true, all certificates are accepted.
        /// </summary>
        public static SslStream Connect(string host, int port, bool noSslVerify = false)
        {
            Console.WriteLine("[SSL] Connecting to {0}:{1} (TLS, cert {2})...",
                host, port, noSslVerify ? "validation disabled" : "pinning enabled");

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
                Console.WriteLine("[SSL] TLS handshake succeeded — certificate accepted");
            }
            catch (AuthenticationException ex)
            {
                Console.WriteLine("[SSL] TLS handshake FAILED: {0}", ex.Message);
                client.Close();
                throw;
            }

            return sslStream;
        }

        // ── Step 2: Send Beacon ──────────────────────────────────────

        /// <summary>
        /// Send a length-prefixed encrypted beacon over the TLS channel.
        /// </summary>
        public static void SendBeacon(SslStream ssl, byte[] encryptedBeacon)
        {
            Console.WriteLine("[SSL] Sending {0} encrypted bytes...", encryptedBeacon.Length);

            byte[] lenPrefix = BitConverter.GetBytes(encryptedBeacon.Length);
            ssl.Write(lenPrefix, 0, lenPrefix.Length);
            ssl.Write(encryptedBeacon, 0, encryptedBeacon.Length);
            ssl.Flush();

            Console.WriteLine("[SSL] Beacon sent successfully");
        }

        // ── Step 3: Verify Server ACK ────────────────────────────────

        /// <summary>
        /// Read the server's ACK response, decrypt if encrypted, and verify
        /// it echoes the original beacon. The expected format (after decryption
        /// if applicable) is "ACK{&lt;original_beacon&gt;}".
        /// This acts as server authentication — a valid encrypted ACK proves
        /// the server holds the shared key and understood the protocol.
        /// A plaintext ACK is accepted with a warning.
        /// </summary>
        public static bool VerifyServerAck(SslStream ssl, string originalBeacon)
        {
            Console.WriteLine("[SSL] Reading server ACK...");

            // Read length-prefixed response
            byte[] lenBuf = new byte[4];
            int read = ssl.Read(lenBuf, 0, 4);
            if (read < 4)
            {
                Console.WriteLine("[SSL] No ACK received (server closed connection)");
                return false;
            }

            int respLen = BitConverter.ToInt32(lenBuf, 0);
            if (respLen <= 0 || respLen > 65536)
            {
                Console.WriteLine("[SSL] Invalid ACK length: {0}", respLen);
                return false;
            }

            byte[] respBuf = new byte[respLen];
            int totalRead = 0;
            while (totalRead < respLen)
            {
                int n = ssl.Read(respBuf, totalRead, respLen - totalRead);
                if (n <= 0) break;
                totalRead += n;
            }

            if (totalRead < respLen)
            {
                Console.WriteLine("[SSL] Incomplete ACK ({0}/{1} bytes)", totalRead, respLen);
                return false;
            }

            Console.WriteLine("[SSL] Received ACK ({0} bytes)", totalRead);

            // Determine whether the response is encrypted (AES-CBC produces
            // ciphertext whose length is always a multiple of the block size)
            string ack;
            bool wasEncrypted;
            if (totalRead % 16 == 0)
            {
                try
                {
                    ack = CryptoChannel.Decrypt(respBuf);
                    wasEncrypted = true;
                }
                catch
                {
                    // Not valid ciphertext despite being block-aligned — treat as plaintext
                    ack = Encoding.UTF8.GetString(respBuf, 0, totalRead);
                    wasEncrypted = false;
                }
            }
            else
            {
                ack = Encoding.UTF8.GetString(respBuf, 0, totalRead);
                wasEncrypted = false;
            }

            if (!wasEncrypted)
                Console.WriteLine("[SSL] WARNING — server ACK was not encrypted");

            // Verify: ACK must wrap the beacon as ACK{<beacon>}
            if (!ack.StartsWith(AckPrefix) || ack[ack.Length - 1] != AckSuffix)
            {
                Console.WriteLine("[SSL] REJECTED — response is not a valid ACK");
                return false;
            }

            string echoedBeacon = ack.Substring(AckPrefix.Length, ack.Length - AckPrefix.Length - 1);
            if (echoedBeacon != originalBeacon)
            {
                Console.WriteLine("[SSL] REJECTED — beacon mismatch");
                return false;
            }

            Console.WriteLine("[SSL] VERIFIED — server echoed correct beacon{0}",
                wasEncrypted ? " (encrypted)" : " (plaintext)");
            return true;
        }

        // ── Certificate callbacks ────────────────────────────────────

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
                Console.WriteLine("[SSL] No certificate presented — rejecting");
                return false;
            }

            string thumbprint = certificate.GetCertHashString();
            Console.WriteLine("[SSL] Server certificate thumbprint: {0}", thumbprint);

            if (!string.Equals(thumbprint, PinnedThumbprint, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("[SSL] Thumbprint does NOT match pinned value — rejecting");
                return false;
            }

            Console.WriteLine("[SSL] Thumbprint matches pinned value — accepting");
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
            Console.WriteLine("[SSL] Certificate validation SKIPPED (--no-ssl) — accepting");
            return true;
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
