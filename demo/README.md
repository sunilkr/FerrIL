# FerrIL Demo Target

A .NET Framework 4.0 console application that exercises the three core malware
patterns the FerrIL CLR profiler framework is designed to analyze.

## What It Demonstrates

| Pattern | Code | Profiler Module |
|---------|------|-----------------|
| **SSL Certificate Pinning** | `SslStream` with custom `RemoteCertificateValidationCallback` that checks a pinned thumbprint | `ssl_unpin` / `dotpatch` replaces the wrapper with `return true` |
| **Encrypted Messages** | AES-CBC encrypted beacon and C2 messages | `fntrace` captures plaintext args to `Encrypt()`/`Decrypt()` |
| **Reflective Assembly Loading** | `Assembly.Load(byte[])` and `AppDomain.CurrentDomain.Load(byte[])` on an AES-encrypted embedded DLL | `asmdump` intercepts the `Load` call and dumps the assembly bytes |

## Project Structure

```
demo/
├── build.bat                  # Build script (uses .NET Framework csc.exe)
├── demo-config.json           # Sample FerrIL config targeting this demo
├── FerrILDemo.sln             # Visual Studio solution
├── DemoPayload/
│   ├── DemoPayload.csproj
│   └── Stage2.cs              # Second-stage "payload" loaded reflectively
├── DemoTarget/
│   ├── DemoTarget.csproj
│   ├── Program.cs             # Entry point — runs all three demos
│   ├── CertPinning.cs         # SslStream + pinned cert validation
│   ├── CryptoChannel.cs       # AES encrypt/decrypt for messages
│   ├── AssemblyLoader.cs      # Assembly.Load(byte[]) wrapper
│   └── EmbeddedPayload.cs     # Encrypted payload loading/decryption
└── build/                     # Build output (created by build.bat)
    ├── DemoTarget.exe
    └── DemoPayload.dll
```

## Building

### Using build.bat (no Visual Studio required)

```cmd
cd demo
build.bat
```

This uses `csc.exe` from the .NET Framework installation directory. Outputs go
to `demo\build\`.

### Using Visual Studio / MSBuild

```cmd
msbuild FerrILDemo.sln /p:Configuration=Debug
```

Then copy `DemoPayload.dll` next to `DemoTarget.exe`.

## Running

### Standalone (no profiler)

```cmd
demo\build\DemoTarget.exe
```

The SSL connection will fail (expected — there is no matching server), the
crypto round-trip will succeed, and the reflective load will run the Stage2
payload.

### Under FerrIL Profilers

From the project root, after building both the profiler and the demo:

```cmd
REM Bypass SSL pinning
profile.exe -p ssl_unpin.dll demo\build\DemoTarget.exe

REM Trace encrypted message arguments
profile.exe -p fntrace.dll demo\build\DemoTarget.exe

REM Dump the reflectively-loaded assembly
profile.exe -p asmdump.dll demo\build\DemoTarget.exe

REM Combined: patch + trace using demo-config.json
set COR_PROF_CONFIG_FILE=demo\demo-config.json
profile.exe -p dotpatch.dll demo\build\DemoTarget.exe
```

### Expected Profiler Output

- **ssl_unpin**: The pinned certificate check is bypassed — if a MITM proxy is
  set up, the TLS handshake succeeds regardless of the certificate thumbprint.
- **fntrace**: The plaintext string passed to `CryptoChannel.Encrypt()` appears
  in the profiler log, revealing the beacon content without breaking AES.
- **asmdump**: A file `dump-XXXX.dll` appears in the working directory
  containing the `DemoPayload` assembly bytes, extracted from the
  `Assembly.Load(byte[])` call.

## Design Notes

- **x86 build target**: The demo builds as 32-bit to match the profiler DLLs
  produced by `cargo bd32` / `cargo br32`.
- **.NET Framework 4.0**: Targets the oldest supported framework version. The
  profiler works with 4.7+ but the demo code compiles against 4.0.
- **No real C2**: The SSL demo connects to `demo.example.com:443` which will
  fail gracefully. The point is to exercise the `SslStream` + pinning code path
  so the profiler can intercept it.
- **DemoPayload.dll on disk**: For simplicity, the payload DLL is loaded from
  disk and encrypted/decrypted at runtime. In real malware it would be embedded
  as a byte array or resource. The `Assembly.Load(byte[])` call is identical
  either way.
