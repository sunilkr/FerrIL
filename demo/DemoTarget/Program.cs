using System;
using System.Reflection;

namespace DemoTarget
{
    /// <summary>
    /// FerrIL Demo Target — a .NET loader that:
    ///   1. Decrypts an embedded payload assembly (AES)
    ///   2. Loads it reflectively via Assembly.Load(byte[])
    ///   3. Invokes Stage2.Execute(host, port) by reflection
    ///
    /// The payload (DemoPayload.dll) contains the actual C2 logic:
    ///   - SSL certificate pinning   → ssl_unpin bypasses it
    ///   - Encrypted messaging        → fntrace captures plaintext args
    ///   - The assembly itself        → asmdump dumps the Load(byte[]) buffer
    ///
    /// Usage: DemoTarget.exe [host port] [--wait] [--no-ssl]
    /// </summary>
    internal class Program
    {
        private const string DefaultHost = "demo.example.com";
        private const int DefaultPort = 443;

        static void PrintUsage()
        {
            Console.WriteLine("Usage: DemoTarget.exe [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  <host> <port>   Server IP/hostname and port for the SSL connection");
            Console.WriteLine("  --no-ssl        Skip TLS certificate validation (accept any cert)");
            Console.WriteLine("  --wait          Wait for a keypress before exiting");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  DemoTarget.exe                          (uses {0}:{1})", DefaultHost, DefaultPort);
            Console.WriteLine("  DemoTarget.exe 192.168.1.10 8443");
            Console.WriteLine("  DemoTarget.exe 192.168.1.10 8443 --no-ssl");
            Console.WriteLine("  DemoTarget.exe 192.168.1.10 8443 --no-ssl --wait");
        }

        static void Main(string[] args)
        {
            // ── Parse arguments ──────────────────────────────────────────
            string host = DefaultHost;
            int port = DefaultPort;
            bool wait = false;
            bool noSsl = false;

            int i = 0;
            while (i < args.Length)
            {
                if (args[i] == "--help" || args[i] == "-h")
                {
                    PrintUsage();
                    return;
                }
                else if (args[i] == "--wait")
                {
                    wait = true;
                    i++;
                }
                else if (args[i] == "--no-ssl")
                {
                    noSsl = true;
                    i++;
                }
                else if (i + 1 < args.Length && !args[i].StartsWith("-"))
                {
                    host = args[i];
                    if (!int.TryParse(args[i + 1], out port) || port < 1 || port > 65535)
                    {
                        Console.WriteLine("ERROR: Invalid port '{0}'. Must be 1-65535.", args[i + 1]);
                        return;
                    }
                    i += 2;
                }
                else
                {
                    Console.WriteLine("ERROR: Unexpected argument '{0}'. Use --help for usage.", args[i]);
                    return;
                }
            }

            // ── Banner ───────────────────────────────────────────────────
            Console.WriteLine("═══════════════════════════════════");
            Console.WriteLine("        FerrIL Demo Target         ");            
            Console.WriteLine("═══════════════════════════════════");
            Console.WriteLine();
            Console.WriteLine("PID: {0} | Runtime: {1} | Arch: {2}-bit",
                System.Diagnostics.Process.GetCurrentProcess().Id,
                Environment.Version,
                IntPtr.Size * 8);
            Console.WriteLine("Server: {0}:{1}", host, port);
            if (noSsl)
                Console.WriteLine("TLS certificate validation: DISABLED (--no-ssl)");
            Console.WriteLine();

            // ── Decrypt and load payload ─────────────────────────────────
            Console.WriteLine("=== Reflective Assembly Loading ===");
            byte[] payloadBytes = EmbeddedPayload.GetPayloadBytes();
            if (payloadBytes == null)
            {
                Console.WriteLine("[!] No payload found. Build DemoPayload first.");
                return;
            }

            Assembly payload;
            try
            {
                payload = AssemblyLoader.LoadFromBytes(payloadBytes);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Assembly.Load failed: {0}", ex.Message);
                return;
            }
            Console.WriteLine();

            // ── Invoke Stage2.Execute(host, port, noSsl) by reflection ────
            Console.WriteLine("=== Invoking Stage2 (SSL verify → beacon → server auth) ===");
            try
            {
                Type stage2 = payload.GetType("DemoPayload.Stage2");
                if (stage2 == null)
                {
                    Console.WriteLine("[!] DemoPayload.Stage2 type not found in loaded assembly");
                    return;
                }

                MethodInfo execute = stage2.GetMethod("Execute",
                    BindingFlags.Public | BindingFlags.Static,
                    null,
                    new Type[] { typeof(string), typeof(int), typeof(bool) },
                    null);
                if (execute == null)
                {
                    Console.WriteLine("[!] Stage2.Execute(string, int, bool) method not found");
                    return;
                }

                Console.WriteLine("[Loader] Invoking Stage2.Execute(\"{0}\", {1}, noSsl={2})...", host, port, noSsl);
                string result = (string)execute.Invoke(null, new object[] { host, port, noSsl });
                Console.WriteLine();
                Console.WriteLine("[Loader] Stage2 returned: {0}", result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Stage2 invocation failed: {0}",
                    ex.InnerException != null ? ex.InnerException.Message : ex.Message);
            }

            Console.WriteLine();
            if (wait)
            {
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }
    }
}
