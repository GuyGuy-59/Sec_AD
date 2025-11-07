## GPO Catalog

This document catalogs the Group Policy Objects included in this repository. It consolidates the names from the `GPO/manifest.xml` and the logical groupings from `Config/GPO_config.json`, and provides short, actionable descriptions. Use it as a quick reference when deciding which GPOs to link to which OUs and tiers.

## Table of contents

- [Functional level mapping](#functional-level-mapping)
- [Summary table](#summary-table-all-gpos-verified-where-backups-exist)
- [Verified settings from backups](#verified-settings-from-backups)
- [GPO details (alphabetical)](#gpo-details-alphabetical)
- [Recommended linking](#recommended-linking)



### Functional level mapping

- Common (applies to all environments):
  - Applocker-Enabled
  - Bitlocker-Enabled
  - Bloodhound-Mitigation
  - Exploit-Guard-ASR-Enabled
  - Exploit-Guard-CFA-Enabled
  - Exploit-Guard-NP-Enabled
  - IPv6-Disabled
  - Kerberos-AES-Enabled
  - Kerberos-Armoring-Enabled
  - LAPS-Enabled
  - LDAP-CBT-Enabled
  - LDAP-Client-Signing-Required
  - LDAP-Server-Signing-Required
  - LLMNR-Disabled
  - Logs-Advanced-Server-Enabled / Logs-Advanced-Workstation-Enabled
  - mDNS-Disabled
  - MSCache-Disabled
  - NTLM1-LM-Disabled
  - NTLM-Audit-Enabled
  - NTLMv2-128bits-Required
  - Proxy-Change-Disabled
  - Powershell-Hardened
  - RDP-hijacking-Mitigation
  - RDP-Secure-Connection-Enabled
  - Remote-Credential-Guard-Enabled
  - RPC-Hardened
  - ScreenLock-enabled
  - Secure-NetLogon
  - SMB-Client-Signing-Enabled
  - SMB-Server-Signing-Enabled
  - SMBv1-Disabled
  - SSDP-Disabled
  - TLS-Hardened
  - UAC-Hardened
  - UNC-Paths-Hardened
  - Wdigest-Disabled
  - WebProxyAutoDiscovery-Disabled
  - WPAD-Computer-Disabled
  - WPAD-User-Disabled
  - WScript-Disabled

- Level2016 (Windows Server 2016 and below):
  - LMHASH-Disabled
  - NBT-NS-Disabled

- Level2025 (Windows Server 2025 and above):
  - NBT-NS-New-Disabled
  - SMB-NTLM-Disabled
  - SMB-Client-Encrypt-Required

Note: The exact availability of some GPOs depends on your backup set. Always verify presence in `GPO/manifest.xml` and the corresponding `{GUID}` directory.

## Summary table (all GPOs, verified where backups exist)

| GPO | Level | Key settings (verified or intended) | Source GUID | Verified |
| --- | --- | --- | --- | --- |
| Applocker-Enabled | Common | Enforce AppLocker rules (Publisher/Path/Hash) | - | No |
| [Bitlocker-Enabled](#bitlocker-enabled) | Common | XTS-AES 256 OS/Fixed/Removable; Recovery to AD DS; Require TPM; allow PIN/key | {D40FCAEA-A277-40F6-9B6E-A2BF18E0843D} | Yes |
| [Bloodhound-Mitigation](#bloodhound-mitigation) | Common | SrvsvcSessionInfo registry modification | {C3CA1767-F3D3-4083-9F9A-0F9DD6C92861} | Yes |
| [Exploit-Guard-ASR-Enabled](#exploit-guard-asr-enabled) | Common | Windows Defender ASR rules enabled (19 rules including LSASS protection, Office macro blocking, ransomware protection) | {7E6A7DF9-2F13-4BC2-9C56-425B5406B9EF} | Yes |
| [Exploit-Guard-CFA-Enabled](#exploit-guard-cfa-enabled) | Common | Configure Controlled Folder Access to protect folders from untrusted applications | {F12C5009-1739-46B7-A426-CC52CD10041F} | Yes |
| [Exploit-Guard-NP-Enabled](#exploit-guard-np-enabled) | Common | Enable Network Protection to prevent access to dangerous domains | {87C0251F-0105-423B-9D42-B9042862F1F3} | Yes |
| [IPv6-Disabled](#ipv6-disabled) | Common | HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\DisabledComponents = 0xFF | {18DDEDE5-8AC7-4F68-BD53-0F4FE82CFF6A} | Yes |
| [Kerberos-AES-Enabled](#kerberos-aes-enabled) | Common | Allow AES128/AES256; disable RC4/DES | {5C8C70D6-ADC5-4861-9D33-78BA8925C546} | Yes |
| [Kerberos-Armoring-Enabled](#kerberos-armoring-enabled) | Common | KDC armoring (Always provide claims); Client support enabled | {D8213592-A793-467D-BD6F-FB3BAF1212D6} | Yes |
| [LAPS-Enabled](#laps-enabled) | Common | Backup to AD; encryption enabled; history 1; len 14; age 1d | {9D44F24F-35F8-4BB2-B711-64F5FE3933E8} | Yes |
| [LDAP-CBT-Enabled](#ldap-cbt-enabled) | Common | DC LDAP CBT requirement = Always | {02DE5552-EAA5-40A6-A2E1-A659C1DE57D0} | Yes |
| [LDAP-Client-Signing-Required](#ldap-client-signing-required) | Common | Require LDAP signing (client) | {56653B16-88E2-4947-BF25-B9E90838CBCB} | Yes |
| [LDAP-Server-Signing-Required](#ldap-server-signing-required) | Common | Require LDAP signing (DC) | {5DC701B5-4706-4B72-A3EF-959EC7A9CCB2} | Yes |
| [LLMNR-Disabled](#llmnr-disabled) | Common | Turn off multicast name resolution: Enabled | {D386A8E5-6739-400B-9D96-027DDFCD0252} | Yes |
| [LMHASH-Disabled](#lmhash-disabled) | Level2016 | HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash = 1 | {5DA34663-85C7-4EBA-9AFE-63B6CE5A9D5B} | Yes |
| [Logs-Advanced-Server-Enabled](#logs-advanced-server-enabled) | Common | Advanced Audit: Logon=Success/Failure, ProcCreation=Success, Kerberos=Success, File Share=Success/Failure, more | {84C66152-0AA5-42EF-8CA1-7D4476BEB88E} | Yes |
| [Logs-Advanced-Workstation-Enabled](#logs-advanced-workstation-enabled) | Common | Advanced Audit (workstations) incl. Logon, ProcCreation, File Share, etc. | {950CB7EF-E5E4-4F22-834E-BB845BB33652} | Yes |
| [mDNS-Disabled](#mdns-disabled) | Common | HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS = 0 | {34EFE6F0-1266-4EF9-B52C-1B3D4FF0713B} | Yes |
| [MSCache-Disabled](#mscache-disabled) | Common | CachedLogonsCount = 1 | {33CE3E1D-8AFD-4A96-A89C-CF9776A8C67F} | Yes |
| [NBT-NS-Disabled](#nbt-ns-disabled) | Level2016 | PowerShell script: NBT-NS-Disabled.ps1 (Startup) | {6CDB3BDF-A907-4DF8-8678-AA3D962761C5} | Yes |
| [NBT-NS-New-Disabled](#nbt-ns-new-disabled) | Level2025 | Configure NetBIOS settings: Disable NetBIOS name resolution | {D04765E7-21F8-4262-BF17-BA6915EA3E3C} | Yes |
| [NTLM-Audit-Enabled](#ntlm-audit-enabled) | Common | AuditReceivingNTLMTraffic=Enable all; Netlogon AuditNTLMInDomain=Enable all | {C4614F9E-8588-4538-9D4B-79A9D7B78FC5} | Yes |
| [NTLM-Disabled](#ntlm-disabled) | Common | Network security: Restrict NTLM: NTLM authentication in this domain = Deny all | {204AB18D-6CED-47A5-BDB0-F1EAA927E589} | Yes |
| [NTLM1-LM-Disabled](#ntlm1-lm-disabled) | Common | LmCompatibilityLevel=5; allownullsessionfallback=0; UseMachineId=1 | {F7B2DAF3-419E-434A-B2EA-878A9A4CF50D} | Yes |
| [NTLMv2-128bits-Required](#ntlmv2-128bits-required) | Common | NTLMMinClientSec/NTLMMinServerSec: Require NTLMv2 session security + 128-bit | {8D43D93F-9881-4B2D-860D-0E55F8BADE11} | Yes |
| [Powershell-Hardened](#powershell-hardened) | Common | Module Logging=*; Script Block Logging=Enabled; Transcription=Enabled; Execution Policy=RemoteSigned | {5B6C5DC9-5736-48DD-BA2D-54421ED148D0} | Yes |
| [Proxy-Change-Disabled](#proxy-change-disabled) | Common | Prevent changing proxy settings: Enabled | {11D658FD-B6A9-40EB-A4DF-DAD4AEFEFE49} | Yes |
| [RDP-hijacking-Mitigation](#rdp-hijacking-mitigation) | Common | Do not allow passwords to be saved; End session when time limits reached; Set time limit for disconnected sessions: 1 minute | {59AC93A5-1EA4-4DB7-8205-1904BB465712} | Yes |
| [RDP-Secure-Connection-Enabled](#rdp-secure-connection-enabled) | Common | Require SSL (TLS 1.0) security layer; Require NLA; High encryption level | {CD6C9404-6999-4A43-BD2B-7CEE359FB50F} | Yes |
| [Remote-Credential-Guard-Enabled](#remote-credential-guard-enabled) | Common | Require Remote Credential Guard to prevent credential delegation during RDP connections | {98713E77-38FA-43CD-8D6A-E2B6FDA9B788} | Yes |
| [RPC-Hardened](#rpc-hardened) | Common | Enable RPC Endpoint Mapper Client Authentication; Restrict Unauthenticated RPC clients: Authenticated | {D9660FAF-7936-4E4C-BC7B-0FFB26E9A017} | Yes |
| [ScreenLock-enabled](#screenlock-enabled) | Common | Enable screensaver; password protect; timeout=600s | {B83BEEC6-9AFD-46DC-B5DF-E6DD0963EDAD} | Yes |
| [Secure-NetLogon](#secure-netlogon) | Common | RequireSignOrSeal, SealSecureChannel, RequireStrongKey = 1; DisablePasswordChange = 0; MaximumPasswordAge = 30d | {D4F07B79-4AA2-4DA2-96DE-FEE6612899C7} | Yes |
| [SMB-Client-Encrypt-Required](#smb-client-encrypt-required) | Level2025 | Require Encryption: Enabled | {4985D82E-1B74-46EF-AD73-33CE0AC84CDC} | Yes |
| [SMB-Client-Signing-Enabled](#smb-client-signing-enabled) | Common | Client signing if/always: Enabled; no plaintext | {4C681DD9-AD37-46A3-AFCD-F8E529E5D11B} | Yes |
| [SMB-NTLM-Disabled](#smb-ntlm-disabled-windows-2025) | Level2025 | SMB client blocks NTLM | {EB9FE2D4-776F-45DB-92EA-FE19D42F03E7} | Yes |
| [SMB-Server-Signing-Enabled](#smb-server-signing-enabled) | Common | Server signing if/always: Enabled | {26EB3D1F-4C89-40D1-A11E-2A4C8A31A669} | Yes |
| [SMBv1-Disabled](#smbv1-disabled) | Common | HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0 | {AE8DF7F8-5623-4C10-B6A7-C0E9BE598BB7} | Yes |
| [SSDP-Disabled](#ssdp-disabled) | Common | SSDPSRV service: Disabled | {0FBBB029-356A-46F8-8158-5CB1C668EDAC} | Yes |
| [TLS-Hardened](#tls-hardened) | Common | Disable SSL 3.0 and TLS 1.0/1.1 (Client/Server); set DisabledByDefault=1 | {C3114819-BA13-42DF-9123-049D7AFB83E7} | Yes |
| [UAC-Hardened](#uac-hardened) | Common | EnableLUA=1; PromptOnSecureDesktop=1; FilterAdministratorToken=1; ConsentPromptBehaviorAdmin=2; ConsentPromptBehaviorUser=1; EnableVirtualization=1 | {950CB7EF-E5E4-4F22-834E-BB845BB33652} | Yes |
| [UNC-Paths-Hardened](#unc-paths-hardened) | Common | \\*\\SYSVOL and \\*\\NETLOGON: RequireMutualAuthentication=1, RequireIntegrity=1 | {88D3A452-EE6A-43FD-9318-E35139F67AF9} | Yes |
| [Wdigest-Disabled](#wdigest-disabled) | Common | HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0 | {58F19C43-E9A3-4FB4-83B3-60775BD54BE2} | Yes |
| [WebProxyAutoDiscovery-Disabled](#webproxyautodiscovery-disabled) | Common | WinHttpAutoProxySvc Start=4; AutoDetect=0 | {11BBFDC3-5A7E-495B-A275-98F9D6CA666B} | Yes |
| [WPAD-Computer-Disabled](#wpad-computer-disabled) | Common | HKLM\\...\\WinHttp\\DisableWpad = 1 | {C82210F2-407C-49FB-A2AF-F394EFEE5AC2} | Yes |
| [WPAD-User-Disabled](#wpad-user-disabled) | Common | HKCU\\...\\Internet Settings\\AutoDetect = 0 | {E0A0C5FB-86D3-4B59-9DEF-26C91030E19C} | Yes |
| [WScript-Disabled](#wscript-disabled) | Common | HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\Enabled = 0 | {0D2A290C-6F47-4F94-B144-63E091DD8A2A} | Yes |

### GPO details (alphabetical)

- Applocker-Enabled: Enables AppLocker rules (publisher/path/hash) to restrict unapproved code execution.
- Bitlocker-Enabled: Enforces BitLocker drive encryption, recovery key escrow to AD, TPM usage, and strong algorithms.
- Exploit-Guard-ASR-Enabled: Enables Windows Defender Attack Surface Reduction (ASR) rules to block common attack techniques including credential theft, malicious scripts, Office macros, and ransomware.
- Exploit-Guard-CFA-Enabled: Enables Windows Defender Controlled Folder Access to protect folders from untrusted applications and prevent ransomware attacks.
- Exploit-Guard-NP-Enabled: Enables Windows Defender Network Protection to prevent access to dangerous domains that may host phishing scams, exploit-hosting sites, and other malicious content.
- Bloodhound-Mitigation: Reduces BloodHound attack surface by modifying SrvsvcSessionInfo registry ACL to restrict session enumeration.
- IPv6-Disabled: Disables IPv6 where it is not required, reducing protocol surface.
- Kerberos-AES-Enabled: Prefers/forces AES for Kerberos; disables weak ciphers where possible.
- Kerberos-Armoring-Enabled: Enables Kerberos FAST (armoring) to protect against downgrade and ticket theft.
- LAPS-Enabled: Enables Windows LAPS password rotation and secure storage in AD. Note: add your LAPS readers in the "Configure authorized password decryptors" setting.
- LDAP-CBT-Enabled: Enables LDAP Channel Binding Tokens to mitigate relay attacks.
- LDAP-Client-Signing-Required: Requires LDAP signing on clients.
- LDAP-Server-Signing-Required: Requires LDAP signing on DCs.
- LLMNR-Disabled: Disables LLMNR to reduce name resolution attacks (responder/relay).
- Logs-Advanced-Server-Enabled: Enables comprehensive advanced audit logging on servers (logon, process creation, Kerberos, file share, directory service, account management, etc.)
- Logs-Advanced-Workstation-Enabled: Enables comprehensive advanced audit logging on workstations (logon, process creation, file share, account management, etc.)
- mDNS-Disabled: Disables multicast DNS (mDNS) to prevent uncontrolled local discovery and reduce attack surface.
- MSCache-Disabled: Disables or minimizes cached logons.
- NBT-NS-Disabled: Disables NetBIOS over TCP/IP using PowerShell script (Level2016 method).
- NBT-NS-New-Disabled: Disables NetBIOS over TCP/IP using the newer registry-based method (Windows 10/11+).
- NTLM-Audit-Enabled: Audits NTLM usage to support later blocking.
- NTLM-Disabled: Completely disables NTLM authentication in the domain (Deny all).
- NTLM1-LM-Disabled: Disables LM and NTLMv1 authentication.
- NTLMv2-128bits-Required: Requires NTLMv2 and 128-bit encryption when NTLM is still in use.
- Powershell-Hardened: Enables PowerShell module logging (*), script block logging, transcription, and sets execution policy to RemoteSigned.
- Proxy-Change-Disabled: Prevents user-level proxy changes (mitigates WPAD/proxy hijack scenarios).

- RDP-hijacking-Mitigation: Mitigates RDP session hijacking by disabling password saving, enforcing session timeouts, and limiting disconnected sessions.
- RDP-Secure-Connection-Enabled: Requires SSL (TLS 1.0) security layer for RDP connections, enforces Network Level Authentication, and sets encryption level to High.
- Remote-Credential-Guard-Enabled: Enables Remote Credential Guard to prevent credential delegation during RDP connections, protecting against pass-the-hash and credential theft attacks.
- RPC-Hardened: Requires RPC authentication and restricts unauthenticated clients.
- ScreenLock-enabled: Enforces screen lock timeout and secure unlock.
- Secure-NetLogon: Hardens NetLogon compatibility, requires signing/sealing, mitigates relay.
- SMB-Client-Encrypt-Required: Requires SMB encryption on the client for SMB 3+ when supported.
- SMB-Client-Signing-Enabled: Requires SMB signing on clients.
- SMB-NTLM-Disabled: Blocks NTLM (LM, NTLM, NTLMv2) authentication for SMB client connections (Windows 2025+).
- SMB-Server-Signing-Enabled: Requires SMB signing on servers.
- SMBv1-Disabled: Disables SMBv1 protocol via registry setting (SMB1 = 0).
- SSDP-Disabled: Disables SSDP/UPnP.
- TLS-Hardened: Disables old SSL/TLS; enforces modern TLS versions 
- UAC-Hardened: Tightens UAC prompts and elevation rules; enforces Secure Desktop.
- UNC-Paths-Hardened: Enables UNC hardening (mutual auth, integrity, privacy) on sensitive shares.
- Wdigest-Disabled: Disables WDigest to avoid reversible credential storage in memory.
- WebProxyAutoDiscovery-Disabled: Disables OS-level auto-proxy discovery.
- WPAD-Computer-Disabled: Disables WPAD in the computer context.
- WPAD-User-Disabled: Disables WPAD in the user context.
- WScript-Disabled: Disables Windows Script Host when not required.

### Recommended linking

- Domain Controllers (Tier 0): Kerberos*, LDAP*, Secure-NetLogon, SMB-Server-Signing-Enabled, NTLM-*, TLS-Hardened, Logs.*
- Member Servers (Tier 1): AppLocker (after testing), RDP-*, RPC-Hardened, SMB-Client/Server-Signing, TLS-Hardened, Logs.*
- Workstations (Tier 2): AppLocker, disable LLMNR/mDNS/SSDP/WPAD/WScript, ScreenLock, UAC, PowerShell hardening, SMBv1-Disabled.

Always validate in pre-production, monitor NTLM audit before enforcement, and test for application compatibility (AppLocker/PowerShell/TLS).

## Verified settings from backups
<a id="bitlocker-enabled"></a>
### Bitlocker-Enabled

- Choose drive encryption method and cipher strength: Enabled
  - Operating system drives: XTS-AES 256-bit
  - Fixed data drives: XTS-AES 256-bit
  - Removable data drives: XTS-AES 256-bit
- Choose how BitLocker-protected operating system drives can be recovered: Enabled
  - Allow data recovery agent: Enabled
  - Allow 48-digit recovery password: Enabled
  - Allow 256-bit recovery key: Enabled
  - Save BitLocker recovery information to AD DS: Enabled (Store recovery passwords and key packages)
  - Do not enable BitLocker until recovery information is stored to AD DS: Enabled
- Require additional authentication at startup: Enabled
  - Allow BitLocker without a compatible TPM: Disabled
  - Configure TPM startup: Require TPM
  - Configure TPM startup PIN: Allow startup PIN with TPM
  - Configure TPM startup key: Allow startup key with TPM
  - Configure TPM startup key and PIN: Allow startup key and PIN with TPM
  - **Policy**: Enable comprehensive BitLocker drive encryption with strong security controls
  - **Description**: Enforces BitLocker encryption with XTS-AES 256-bit, TPM requirements, and AD recovery
  - **Settings**:
    - Drive encryption: XTS-AES 256-bit for all drive types
    - Recovery: AD DS storage, multiple recovery methods
    - Authentication: TPM required, PIN/key options
  - **Impact**: Encrypts all drives with strong encryption and secure recovery
  - **Security Benefit**: Protects data at rest and prevents unauthorized access to drives
  - **Category**: Security/Encryption
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="bloodhound-mitigation"></a>
### Bloodhound-Mitigation

- SrvsvcSessionInfo registry modification: Modified DefaultSecurity ACL to restrict session enumeration
  - **Policy**: Mitigate BloodHound attack surface by restricting session enumeration
  - **Description**: Modifies registry ACL to prevent BloodHound from enumerating user sessions
  - **Setting**: SrvsvcSessionInfo registry modification: Modified DefaultSecurity ACL to restrict session enumeration
  - **Impact**: Reduces attack surface for BloodHound and similar enumeration tools
  - **Security Benefit**: Prevents lateral movement reconnaissance and session enumeration
  - **Category**: Security/Attack Surface Reduction
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="exploit-guard-asr-enabled"></a>
### Exploit-Guard-ASR-Enabled

- Windows Defender Attack Surface Reduction (ASR) Rules: All 19 rules enabled (Block mode)
  - **Policy**: Enable Windows Defender Attack Surface Reduction (ASR) rules
  - **Description**: Configures Windows Defender ASR rules to block common attack techniques and malware behaviors
  - **Registry Path**: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules
  - **Settings**:
    - 56A863A9-875E-4185-98A7-B882C64B5CE5 = 1: Block abuse of exploited vulnerable signed drivers
    - 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C = 1: Block Adobe Reader from creating child processes
    - D4F940AB-401B-4EFC-AADC-AD5F3C50688A = 1: Block all Office applications from creating child processes
    - 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 = 1: Block credential stealing from the Windows local security authority subsystem (lsass.exe)
    - BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 = 1: Block executable content from email client and webmail
    - 01443614-CD74-433A-B99E-2ECDC07BFC25 = 1: Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    - 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC = 1: Block execution of potentially obfuscated scripts
    - D3E037E1-3EB8-44C8-A917-57927947596D = 1: Block JavaScript or VBScript from launching downloaded executable content
    - 3B576869-A4EC-4529-8536-B80A7769E899 = 1: Block Office applications from creating executable content
    - 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 = 1: Block Office applications from injecting code into other processes
    - 26190899-1602-49E8-8B27-EB1D0A1CE869 = 1: Block Office communication application from creating child processes
    - E6DB77E5-3DF2-4CF1-B95A-636979351E5B = 1: Block persistence through WMI event subscription
    - D1E49AAC-8F56-4280-B9BA-993A6D77406C = 1: Block process creations originating from PSExec and WMI commands
    - B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 = 1: Block untrusted and unsigned processes that run from USB
    - 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B = 1: Block Win32 API calls from Office macros
    - C1DB55AB-C21A-4637-BB3F-A12568109D35 = 1: Use advanced protection against ransomware
    - A8F5898E-1DC8-49A9-9878-85004B8A61E6 = 1: Block Webshell creation for Servers
    - 33DDEDF1-C6E0-47CB-833E-DE6133960387 = 1: Block rebooting machine in Safe Mode
    - C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB = 1: Block use of copied or impersonated system tools
  - **Impact**: Blocks common attack techniques including credential theft, malicious Office macros, script execution, ransomware, and lateral movement techniques
  - **Security Benefit**: Provides defense-in-depth protection against modern attack techniques and malware behaviors, significantly reducing attack surface
  - **Category**: Security/Attack Surface Reduction
  - **Compatibility**: Windows 10 1709+ and Windows Server 2019+ (requires Windows Defender Antivirus)
  - **Note**: Rule values: 0 = Disabled, 1 = Block, 2 = Audit (Warn). This GPO sets all rules to 1 (Block mode)

<a id="exploit-guard-cfa-enabled"></a>
### Exploit-Guard-CFA-Enabled

- Configure Controlled folder access: Enabled
  - **Policy**: Enable Windows Defender Controlled Folder Access (CFA)
  - **Description**: Protects folders from untrusted applications to prevent ransomware attacks and unauthorized file modifications
  - **Setting**: Configure Controlled folder access: Enabled
  - **Impact**: Blocks untrusted applications from modifying or deleting files in protected folders and writing to disk sectors
  - **Security Benefit**: Prevents ransomware attacks and unauthorized file modifications by untrusted applications
  - **Category**: Security/Attack Surface Reduction
  - **Compatibility**: Windows 10 1709+ and Windows Server 2019+ (requires Windows Defender Antivirus)
  - **Note**: Default system folders are automatically protected. Additional folders can be configured in "Configure protected folders" setting.

<a id="exploit-guard-np-enabled"></a>
### Exploit-Guard-NP-Enabled

- Prevent users and apps from accessing dangerous websites: Enabled
  - **Policy**: Enable Windows Defender Network Protection
  - **Description**: Prevents employees from using any application to access dangerous domains that may host phishing scams, exploit-hosting sites, and other malicious content
  - **Setting**: Prevent users and apps from accessing dangerous websites: Enabled
  - **Impact**: Blocks access to dangerous domains and malicious websites
  - **Security Benefit**: Prevents access to phishing sites, exploit-hosting sites, and other malicious content on the Internet
  - **Category**: Security/Network Protection
  - **Compatibility**: Windows 10 1709+ and Windows Server 2019+ (requires Windows Defender Antivirus)
  - **Note**: Can be configured in Block mode or Audit mode. Block mode prevents access, while Audit mode logs attempts without blocking.

<a id="ipv6-disabled"></a>
### IPv6-Disabled

- HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents = 0xFF
  - **Policy**: Disable IPv6 protocol where not required
  - **Description**: Disables IPv6 to reduce protocol surface and potential attack vectors
  - **Registry Setting**: HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents = 0xFF
  - **Impact**: Prevents IPv6-based attacks and reduces network complexity
  - **Security Benefit**: Reduces attack surface by eliminating unused protocol stack
  - **Category**: Network/Protocol
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="kerberos-aes-enabled"></a>
### Kerberos-AES-Enabled

- Network security: Configure encryption types allowed for Kerberos (SupportedEncryptionTypes):
  - AES128_HMAC_SHA1: true
  - AES256_HMAC_SHA1: true
  - RC4_HMAC_MD5: false
  - DES_CBC_CRC: false
  - DES_CBC_MD5: false
  - Future encryption types: true
  - **Policy**: Configure Kerberos encryption types to use only strong algorithms
  - **Description**: Forces Kerberos to use only AES encryption and disables weak RC4 and DES algorithms
  - **Settings**: Network security: Configure encryption types allowed for Kerberos
    - AES128_HMAC_SHA1: Enabled
    - AES256_HMAC_SHA1: Enabled
    - RC4_HMAC_MD5: Disabled
    - DES_CBC_CRC: Disabled
    - DES_CBC_MD5: Disabled
    - Future encryption types: Enabled
  - **Impact**: Ensures only strong encryption algorithms are used for Kerberos authentication
  - **Security Benefit**: Prevents downgrade attacks and eliminates vulnerabilities in weak encryption algorithms
  - **Category**: Security/Authentication
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="kerberos-armoring-enabled"></a>
### Kerberos-Armoring-Enabled

- KDC support for claims/compound authentication and Kerberos armoring: Enabled
- Option: Always provide claims
- Kerberos client support for claims/compound authentication and armoring: Enabled
  - **Policy**: Enable Kerberos armoring (FAST) for enhanced security
  - **Description**: Enables Kerberos Flexible Authentication Secure Tunneling (FAST) to protect against downgrade attacks and ticket theft
  - **Settings**: 
    - KDC support for claims/compound authentication and Kerberos armoring: Enabled
    - Option: Always provide claims
    - Kerberos client support for claims/compound authentication and armoring: Enabled
  - **Impact**: Provides additional protection for Kerberos authentication against relay and downgrade attacks
  - **Security Benefit**: Prevents ticket theft and man-in-the-middle attacks on Kerberos authentication
  - **Category**: Security/Authentication
  - **Compatibility**: Windows Server 2012+ and Windows 8+

<a id="laps-enabled"></a>
### LAPS-Enabled

- Configure password backup directory: Enabled (Active Directory)
- Configure size of encrypted password history: Enabled (1)
- Enable password encryption: Enabled
- Password Settings: Enabled
  - Password Complexity: Large letters + small letters + numbers
  - Password Length: 14
  - Password Age (Days): 1
  - **Policy**: Enable Windows Local Administrator Password Solution (LAPS)
  - **Description**: Automatically manages and rotates local administrator passwords with secure storage in AD
  - **Settings**:
    - Configure password backup directory: Active Directory
    - Configure size of encrypted password history: 1
    - Enable password encryption: Enabled
    - Password Complexity: Large letters + small letters + numbers
    - Password Length: 14
    - Password Age (Days): 1
  - **Impact**: Automatically rotates local admin passwords and stores them securely in AD
  - **Security Benefit**: Prevents lateral movement using default or weak local admin passwords
  - **Category**: Security/Password Management
  - **Compatibility**: Windows Server 2012+ and Windows 8+

<a id="ldap-cbt-enabled"></a>
### LDAP-CBT-Enabled

- Domain controller: LDAP server channel binding token requirements: Always
  - **Policy**: Enable LDAP Channel Binding Tokens (CBT) for enhanced security
  - **Description**: Requires LDAP Channel Binding Tokens to prevent relay attacks
  - **Setting**: Domain controller: LDAP server channel binding token requirements: Always
  - **Impact**: Ensures LDAP connections are bound to the underlying transport channel
  - **Security Benefit**: Prevents LDAP relay attacks and man-in-the-middle attacks
  - **Category**: Security/LDAP
  - **Compatibility**: Windows Server 2012+ and Windows 8+

<a id="ldap-client-signing-required"></a>
### LDAP-Client-Signing-Required

- Network security: LDAP client signing requirements: Require signing
  - **Policy**: Require LDAP client signing for all LDAP connections
  - **Description**: Forces all LDAP client connections to use signing to prevent tampering
  - **Setting**: Network security: LDAP client signing requirements: Require signing
  - **Impact**: Ensures all LDAP traffic is signed and protected against tampering
  - **Security Benefit**: Prevents LDAP relay attacks and data tampering
  - **Category**: Security/LDAP
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="ldap-server-signing-required"></a>
### LDAP-Server-Signing-Required

- Domain controller: LDAP server signing requirements: Require signing
  - **Policy**: Require LDAP server signing on domain controllers
  - **Description**: Forces domain controllers to require signing for all LDAP connections
  - **Setting**: Domain controller: LDAP server signing requirements: Require signing
  - **Impact**: Ensures all LDAP server traffic is signed and protected against tampering
  - **Security Benefit**: Prevents LDAP relay attacks and data tampering on domain controllers
  - **Category**: Security/LDAP
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="llmnr-disabled"></a>
### LLMNR-Disabled

- Turn off multicast name resolution: Enabled
  - **Policy**: Disable Link-Local Multicast Name Resolution (LLMNR)
  - **Description**: Prevents the system from using LLMNR for name resolution
  - **Setting**: Turn off multicast name resolution: Enabled
  - **Impact**: Prevents LLMNR-based attacks and reduces attack surface
  - **Security Benefit**: Mitigates responder attacks and name resolution poisoning
  - **Category**: Network/Name Resolution
  - **Compatibility**: Windows Vista+ and Windows Server 2008+

<a id="lmhash-disabled"></a>
### LMHASH-Disabled

- HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash = 1
  - **Policy**: Disable LM hash storage for passwords
  - **Description**: Prevents Windows from storing LM hashes of passwords in memory
  - **Registry Setting**: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash = 1
  - **Impact**: Prevents LM hash storage and reduces password cracking risk
  - **Security Benefit**: Eliminates weak LM hash vulnerabilities and prevents rainbow table attacks
  - **Category**: Security/Password
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="logs-advanced-server-enabled"></a>
### Logs-Advanced-Server-Enabled

- Advanced Audit Configuration (servers):
  - Audit Logon: Success and Failure
  - Audit Process Creation: Success
  - Audit Kerberos Authentication Service: Success and Failure
  - Audit Kerberos Service Ticket Operations: Failure
  - Audit File Share: Success and Failure
  - Audit Detailed File Share: Failure
  - Audit User Account Management: Success and Failure
  - Audit Directory Service Access: Failure
  - Audit Directory Service Changes: Success
  - Audit Directory Service Replication: Success
  - Audit Credential Validation: Success and Failure
  - Audit Other Logon/Logoff Events: Success and Failure
  - Audit Account Lockout: Failure
  - Audit Security Group Management: Success
  - Audit Computer Account Management: Success
  - Audit Other Account Management Events: Success
  - Audit Group Membership: Success
  - Audit PNP Activity: Success
  - Audit Other Object Access Events: Success and Failure
  - Audit Removable Storage: Success and Failure
  - Audit Audit Policy Change: Success
  - Audit Authentication Policy Change: Success
  - Audit MPSSVC Rule-Level Policy Change: Success and Failure
  - Audit Other Policy Change Events: Failure
  - Audit Sensitive Privilege Use: Success and Failure
  - Audit Other System Events: Success and Failure
  - Audit Security State Change: Success
  - Audit Security System Extension: Success
  - Audit System Integrity: Success and Failure

<a id="logs-advanced-workstation-enabled"></a>
### Logs-Advanced-Workstation-Enabled

- Advanced Audit Configuration (workstations):
  - Audit Logon: Success and Failure
  - Audit Process Creation: Success
  - Audit File Share: Success and Failure
  - Audit Detailed File Share: Failure
  - Audit User Account Management: Success and Failure
  - Audit Security Group Management: Success
  - Audit Group Membership: Success
  - Audit Account Lockout: Failure
  - Audit Other Logon/Logoff Events: Success and Failure
  - Audit Other Object Access Events: Success and Failure
  - Audit Removable Storage: Success and Failure
  - Audit Audit Policy Change: Success
  - Audit Authentication Policy Change: Success
  - Audit MPSSVC Rule-Level Policy Change: Success and Failure
  - Audit Other Policy Change Events: Success and Failure
  - Audit Sensitive Privilege Use: Success
  - Audit Other System Events: Success and Failure
  - Audit Security State Change: Success
  - Audit Security System Extension: Success
  - Audit System Integrity: Success and Failure
  - Audit Credential Validation: Success and Failure
  - Audit PNP Activity: Success

<a id="mdns-disabled"></a>
### mDNS-Disabled

- HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS = 0
  - **Policy**: Disable multicast DNS (mDNS) service
  - **Description**: Prevents the system from using multicast DNS for local name resolution
  - **Registry Setting**: HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS = 0
  - **Impact**: Prevents uncontrolled local discovery and reduces attack surface
  - **Security Benefit**: Mitigates potential information disclosure and attack vectors
  - **Category**: Network/DNS
  - **Compatibility**: Windows 10/11 and Windows Server 2016+

<a id="mscache-disabled"></a>
### MSCache-Disabled

- CachedLogonsCount = 1
  - **Policy**: Minimize cached logon credentials
  - **Description**: Reduces the number of cached logon credentials to minimize offline attack surface
  - **Registry Setting**: CachedLogonsCount = 1
  - **Impact**: Limits cached credentials and reduces offline attack potential
  - **Security Benefit**: Prevents offline password attacks and reduces credential exposure
  - **Category**: Security/Password
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="nbt-ns-disabled"></a>
### NBT-NS-Disabled

- PowerShell script: NBT-NS-Disabled.ps1 (Startup script)
  - **Policy**: Disable NetBIOS over TCP/IP using PowerShell script
  - **Description**: Uses PowerShell script to disable NetBIOS name resolution (Level2016 method)
  - **Setting**: PowerShell script: NBT-NS-Disabled.ps1 (Startup script)
  - **Impact**: Prevents NetBIOS-based attacks and reduces attack surface
  - **Security Benefit**: Mitigates NetBIOS-based attacks and name resolution poisoning
  - **Category**: Network/Name Resolution
  - **Compatibility**: Windows Server 2016 and below

<a id="nbt-ns-new-disabled"></a>
### NBT-NS-New-Disabled

- Configure NetBIOS settings: Disable NetBIOS name resolution
  - **Policy**: Disable NetBIOS over TCP/IP name resolution
  - **Description**: Prevents the system from using NetBIOS for name resolution
  - **Setting**: Configure NetBIOS settings: Disable NetBIOS name resolution
  - **Impact**: Prevents NetBIOS-based attacks and reduces attack surface
  - **Security Benefit**: Mitigates NetBIOS-based attacks and name resolution poisoning
  - **Category**: Network/Name Resolution
  - **Compatibility**: Windows 10+ and Windows Server 2016+

<a id="ntlm-audit-enabled"></a>
### NTLM-Audit-Enabled

- Network security: Restrict NTLM: Audit Incoming NTLM Traffic = Enable auditing for all accounts
- Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all
  - **Policy**: Enable comprehensive NTLM auditing for security monitoring
  - **Description**: Audits all NTLM authentication attempts to identify usage before blocking
  - **Settings**:
    - Network security: Restrict NTLM: Audit Incoming NTLM Traffic = Enable auditing for all accounts
    - Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all
  - **Impact**: Logs all NTLM authentication events for analysis
  - **Security Benefit**: Enables identification of NTLM usage before implementing blocking
  - **Category**: Security/Auditing
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="ntlm-disabled"></a>
### NTLM-Disabled

- Network security: Restrict NTLM: NTLM authentication in this domain = Deny all
  - **Policy**: Block NTLM (LM, NTLM, NTLMv2) authentication in this domain
  - **Description**: Completely disables NTLM authentication for all domain accounts
  - **Setting**: Network security: Restrict NTLM: NTLM authentication in this domain = Deny all
  - **Impact**: Forces all authentication to use Kerberos or other modern methods
  - **Security Benefit**: Eliminates NTLM vulnerabilities and enforces stronger authentication
  - **Category**: Security/Authentication
  - **Warning**: Ensure all applications and services support Kerberos before enabling
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="ntlm1-lm-disabled"></a>
### NTLM1-LM-Disabled

- Network security: LAN Manager authentication level: Send NTLMv2 response only. Refuse LM & NTLM
- Network security: Allow LocalSystem NULL session fallback: Disabled
- Network security: Allow Local System to use computer identity for NTLM: Enabled
  - **Policy**: Disable weak LM and NTLMv1 authentication
  - **Description**: Forces use of NTLMv2 and disables weak LM/NTLMv1 authentication
  - **Settings**:
    - Network security: LAN Manager authentication level: Send NTLMv2 response only. Refuse LM & NTLM
    - Network security: Allow LocalSystem NULL session fallback: Disabled
    - Network security: Allow Local System to use computer identity for NTLM: Enabled
  - **Impact**: Ensures only strong NTLMv2 authentication is used
  - **Security Benefit**: Prevents downgrade attacks and eliminates weak authentication methods
  - **Category**: Security/Authentication
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="ntlmv2-128bits-required"></a>
### NTLMv2-128bits-Required

- Network security: Minimum session security for NTLM SSP (including secure RPC) clients: Require NTLMv2 session security, Require 128-bit encryption
- Network security: Minimum session security for NTLM SSP (including secure RPC) servers: Require NTLMv2 session security, Require 128-bit encryption
  - **Policy**: Require NTLMv2 and 128-bit encryption for NTLM sessions
  - **Description**: Forces use of NTLMv2 with 128-bit encryption when NTLM is still in use
  - **Settings**:
    - Network security: Minimum session security for NTLM SSP (including secure RPC) clients: Require NTLMv2 session security, Require 128-bit encryption
    - Network security: Minimum session security for NTLM SSP (including secure RPC) servers: Require NTLMv2 session security, Require 128-bit encryption
  - **Impact**: Ensures strong NTLM authentication when NTLM is still required
  - **Security Benefit**: Prevents downgrade attacks and ensures strong encryption for NTLM
  - **Category**: Security/Authentication
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="powershell-hardened"></a>
### Powershell-Hardened

- Turn on Module Logging: Enabled (Module Names: *)
- Turn on PowerShell Script Block Logging: Enabled (Log script block invocation start / stop events: Enabled)
- Turn on PowerShell Transcription: Enabled (Include invocation headers: Disabled)
- Turn on Script Execution: Enabled (Execution Policy: Allow local scripts and remote signed scripts)
  - **Policy**: Enable comprehensive PowerShell logging and security controls
  - **Description**: Enables detailed logging and security controls for PowerShell execution
  - **Settings**:
    - Turn on Module Logging: Enabled (Module Names: *)
    - Turn on PowerShell Script Block Logging: Enabled (Log script block invocation start / stop events: Enabled)
    - Turn on PowerShell Transcription: Enabled (Include invocation headers: Disabled)
    - Turn on Script Execution: Enabled (Execution Policy: Allow local scripts and remote signed scripts)
  - **Impact**: Provides comprehensive logging and security controls for PowerShell
  - **Security Benefit**: Enables detection of malicious PowerShell activity and prevents unauthorized script execution
  - **Category**: Security/Logging
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="proxy-change-disabled"></a>
### Proxy-Change-Disabled

- Prevent changing proxy settings: Enabled
  - **Policy**: Prevent users from changing proxy settings
  - **Description**: Prevents user-level proxy configuration changes to mitigate WPAD attacks
  - **Setting**: Prevent changing proxy settings: Enabled
  - **Impact**: Prevents users from modifying proxy settings
  - **Security Benefit**: Mitigates WPAD/proxy hijack scenarios and unauthorized proxy changes
  - **Category**: Security/Network
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="rdp-hijacking-mitigation"></a>
### RDP-hijacking-Mitigation

- Do not allow passwords to be saved: Enabled
- End session when time limits are reached: Enabled
- Set time limit for disconnected sessions: 1 minute
  - **Policy**: Mitigate RDP session hijacking attacks
  - **Description**: Implements security controls to prevent RDP session hijacking
  - **Settings**:
    - Do not allow passwords to be saved: Enabled
    - End session when time limits are reached: Enabled
    - Set time limit for disconnected sessions: 1 minute
  - **Impact**: Prevents RDP session hijacking and unauthorized access
  - **Security Benefit**: Mitigates RDP-based attacks and session hijacking
  - **Category**: Security/RDP
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="rdp-secure-connection-enabled"></a>
### RDP-Secure-Connection-Enabled

- Require use of specific security layer for remote (RDP) connections: Enabled
  - Security Layer: SSL (TLS 1.0)
- Require user authentication for remote connections by using Network Level Authentication: Enabled
- Set client connection encryption level: Enabled
  - Encryption Level: High Level
  - **Policy**: Require secure RDP connections with SSL/TLS and high encryption
  - **Description**: Enforces SSL (TLS 1.0) security layer for RDP connections, requires Network Level Authentication, and sets encryption level to High
  - **Settings**:
    - Require use of specific security layer for remote (RDP) connections: Enabled (SSL/TLS 1.0)
    - Require user authentication for remote connections by using Network Level Authentication: Enabled
    - Set client connection encryption level: Enabled (High Level)
  - **Impact**: Ensures all RDP connections use SSL/TLS encryption and high-level encryption, with authentication required before session establishment
  - **Security Benefit**: Prevents unencrypted RDP connections, enforces strong encryption, and requires authentication before connection
  - **Category**: Security/RDP
  - **Compatibility**: Windows Server 2008+ and Windows 7+
  - **Note**: SSL (TLS 1.0) is the recommended security layer. High encryption level uses 128-bit encryption for all data.

<a id="remote-credential-guard-enabled"></a>
### Remote-Credential-Guard-Enabled

- Restrict delegation of credentials to remote servers: Enabled
  - **Policy**: Restrict delegation of credentials to remote servers
  - **Description**: Prevents credential delegation during RDP connections by requiring Remote Credential Guard or Restricted Admin mode
  - **Setting**: Use the following restricted mode: Require Remote Credential Guard
  - **Registry Path**: HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
  - **Settings**:
    - AllowProtectedCreds = 1: Enable Remote Credential Guard
  - **Impact**: Prevents participating applications (Remote Desktop Client) from exposing signed-in or supplied credentials to a remote host
  - **Security Benefit**: Protects against pass-the-hash attacks, credential theft, and lateral movement by preventing credential delegation during RDP sessions
  - **Category**: Security/Credentials Delegation
  - **Compatibility**: Windows 10 1607+ and Windows Server 2016+ (Remote Credential Guard requires Windows 10 1607+ / Windows Server 2016+)
  - **Note**: 
    - Remote Credential Guard redirects all requests back to the client device, maintaining access to resources while protecting credentials
    - On Windows 8.1 and Windows Server 2012 R2, enabling this policy enforces Restricted Administration mode regardless of the mode chosen (these versions do not support Remote Credential Guard)
    - Participating apps: Remote Desktop Client
    - Options: "Restrict credential delegation" (allows Restricted Admin or Remote Credential Guard), "Require Remote Credential Guard" (requires Remote Credential Guard), "Require Restricted Admin" (requires Restricted Admin mode)

<a id="rpc-hardened"></a>
### RPC-Hardened

- Enable RPC Endpoint Mapper Client Authentication: Enabled
- Restrict Unauthenticated RPC clients: Authenticated
  - **Policy**: Harden RPC communications and require authentication
  - **Description**: Enforces authentication for RPC communications and restricts unauthenticated clients
  - **Settings**:
    - Enable RPC Endpoint Mapper Client Authentication: Enabled
    - Restrict Unauthenticated RPC clients: Authenticated
  - **Impact**: Ensures all RPC communications are authenticated
  - **Security Benefit**: Prevents unauthorized RPC access and potential privilege escalation
  - **Category**: Security/RPC
  - **Compatibility**: Windows Server 2008+ and Windows 7+


<a id="screenlock-enabled"></a>
### ScreenLock-enabled

- Enable screensaver: Enabled
- Password protect the screensaver: Enabled
- Screen saver timeout: 600 seconds
  - **Policy**: Enforce screen lock timeout and secure unlock
  - **Description**: Automatically locks the screen after inactivity and requires authentication to unlock
  - **Settings**:
    - Enable screensaver: Enabled
    - Password protect the screensaver: Enabled
    - Screen saver timeout: 600 seconds
  - **Impact**: Automatically locks screens after 10 minutes of inactivity
  - **Security Benefit**: Prevents unauthorized access to unattended workstations
  - **Category**: Security/Workstation
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="secure-netlogon"></a>
### Secure-NetLogon

- RequireSignOrSeal = 1
- SealSecureChannel = 1
- RequireStrongKey = 1
- DisablePasswordChange = 0
- MaximumPasswordAge = 30 days
  - **Policy**: Harden NetLogon security and require strong authentication
  - **Description**: Enforces secure NetLogon communications with signing, sealing, and strong keys
  - **Settings**:
    - RequireSignOrSeal = 1
    - SealSecureChannel = 1
    - RequireStrongKey = 1
    - DisablePasswordChange = 0
    - MaximumPasswordAge = 30 days
  - **Impact**: Ensures secure NetLogon communications and regular password changes
  - **Security Benefit**: Prevents NetLogon relay attacks and ensures strong authentication
  - **Category**: Security/NetLogon
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="smb-client-encrypt-required"></a>
### SMB-Client-Encrypt-Required

- Require Encryption: Enabled
  - **Policy**: Require SMB encryption for all client connections
  - **Description**: Forces SMB clients to use encryption for all SMB 3+ connections
  - **Setting**: Require Encryption: Enabled
  - **Impact**: Ensures all SMB client traffic is encrypted
  - **Security Benefit**: Prevents data interception and ensures confidentiality of SMB communications
  - **Category**: Security/SMB
  - **Compatibility**: Windows Server 2025+ and Windows 11+

<a id="smb-client-signing-enabled"></a>
### SMB-Client-Signing-Enabled

- Microsoft network client: Send unencrypted password to third-party SMB servers: Disabled
- Microsoft network client: Digitally sign communications (if server agrees): Enabled
- Microsoft network client: Digitally sign communications (always): Enabled
  - **Policy**: Require SMB client signing and disable unencrypted passwords
  - **Description**: Forces SMB clients to digitally sign communications and prevents sending unencrypted passwords
  - **Settings**:
    - Microsoft network client: Send unencrypted password to third-party SMB servers: Disabled
    - Microsoft network client: Digitally sign communications (if server agrees): Enabled
    - Microsoft network client: Digitally sign communications (always): Enabled
  - **Impact**: Ensures all SMB client traffic is signed and passwords are encrypted
  - **Security Benefit**: Prevents SMB relay attacks and credential theft
  - **Category**: Security/SMB
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="smb-ntlm-disabled-windows-2025"></a>
### SMB-NTLM-Disabled (Windows 2025+)

- Block NTLM (LM, NTLM, NTLMv2): Enabled
  - **Policy**: Block NTLM (LM, NTLM, NTLMv2) for SMB client
  - **Description**: Prevents the SMB client from using NTLM for remote connection authentication
  - **Supported**: Windows Server 2025, Windows 11 and above
  - **Category**: Network/Lanman Workstation
  - **Impact**: SMB client will not use NTLM authentication for remote connections, forcing use of Kerberos or other modern authentication methods

<a id="smb-server-signing-enabled"></a>
### SMB-Server-Signing-Enabled

- Microsoft network server: Digitally sign communications (if client agrees): Enabled
- Microsoft network server: Digitally sign communications (always): Enabled
  - **Policy**: Require SMB server signing for all SMB communications
  - **Description**: Forces SMB servers to digitally sign all communications to prevent tampering
  - **Settings**:
    - Microsoft network server: Digitally sign communications (if client agrees): Enabled
    - Microsoft network server: Digitally sign communications (always): Enabled
  - **Impact**: Ensures all SMB server traffic is signed and protected against tampering
  - **Security Benefit**: Prevents SMB relay attacks and data tampering
  - **Category**: Security/SMB
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="smbv1-disabled"></a>
### SMBv1-Disabled

- HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0
  - **Policy**: Disable SMBv1 protocol
  - **Description**: Prevents the SMB server from accepting SMBv1 connections
  - **Registry Setting**: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0
  - **Impact**: Prevents SMBv1 connections and eliminates SMBv1 vulnerabilities
  - **Security Benefit**: Mitigates EternalBlue, WannaCry, and other SMBv1-based attacks
  - **Category**: Network/SMB
  - **Compatibility**: Ensure all clients support SMBv2/v3 before enabling
  - **Supported**: Windows Server 2008+ and Windows 7+

<a id="ssdp-disabled"></a>
### SSDP-Disabled

- SSDPSRV service: Disabled
  - **Policy**: Disable SSDP/UPnP service
  - **Description**: Prevents the system from using SSDP for device discovery
  - **Setting**: SSDPSRV service: Disabled
  - **Impact**: Prevents SSDP-based attacks and reduces attack surface
  - **Security Benefit**: Mitigates UPnP-based attacks and device discovery vulnerabilities
  - **Category**: Security/Network
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="tls-hardened"></a>
### TLS-Hardened

- SCHANNEL Protocols:
  - SSL 3.0 (Client/Server): Enabled=0, DisabledByDefault=1
  - TLS 1.0 (Client/Server): Enabled=0, DisabledByDefault=1
  - TLS 1.1 (Client/Server): Enabled=0, DisabledByDefault=1
  - **Policy**: Disable weak SSL/TLS protocols and enforce modern encryption
  - **Description**: Disables outdated and vulnerable SSL/TLS protocols to enforce modern encryption standards
  - **Settings**: SCHANNEL Protocols
    - SSL 3.0 (Client/Server): Enabled=0, DisabledByDefault=1
    - TLS 1.0 (Client/Server): Enabled=0, DisabledByDefault=1
    - TLS 1.1 (Client/Server): Enabled=0, DisabledByDefault=1
  - **Impact**: Forces use of TLS 1.2+ and prevents downgrade attacks
  - **Security Benefit**: Eliminates vulnerabilities in weak SSL/TLS protocols
  - **Category**: Security/Encryption
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="uac-hardened"></a>
### UAC-Hardened

- EnableLUA = 1
- PromptOnSecureDesktop = 1
- FilterAdministratorToken = 1
- ConsentPromptBehaviorAdmin = 2
- ConsentPromptBehaviorUser = 1
- EnableVirtualization = 1
  - **Policy**: Harden User Account Control (UAC) security controls
  - **Description**: Enforces strict UAC settings to prevent privilege escalation and unauthorized elevation
  - **Settings**:
    - EnableLUA = 1
    - PromptOnSecureDesktop = 1
    - FilterAdministratorToken = 1
    - ConsentPromptBehaviorAdmin = 2
    - ConsentPromptBehaviorUser = 1
    - EnableVirtualization = 1
  - **Impact**: Enforces secure UAC prompts and prevents unauthorized elevation
  - **Security Benefit**: Prevents privilege escalation attacks and unauthorized administrative access
  - **Category**: Security/Privilege Management
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="unc-paths-hardened"></a>
### UNC-Paths-Hardened

- Hardened UNC Paths list:
  - \\*\\SYSVOL: RequireMutualAuthentication=1, RequireIntegrity=1
  - \\*\\NETLOGON: RequireMutualAuthentication=1, RequireIntegrity=1
  - **Policy**: Enable UNC hardening for sensitive network shares
  - **Description**: Enforces mutual authentication and integrity for critical domain shares
  - **Settings**: Hardened UNC Paths list
    - \\*\\SYSVOL: RequireMutualAuthentication=1, RequireIntegrity=1
    - \\*\\NETLOGON: RequireMutualAuthentication=1, RequireIntegrity=1
  - **Impact**: Ensures secure access to domain policy and logon scripts
  - **Security Benefit**: Prevents UNC path attacks and ensures data integrity
  - **Category**: Security/Network
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="wdigest-disabled"></a>
### Wdigest-Disabled

- HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0
  - **Policy**: Disable WDigest authentication provider
  - **Description**: Prevents WDigest from storing credentials in memory in reversible format
  - **Registry Setting**: HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0
  - **Impact**: Prevents WDigest credential storage and reduces memory-based attacks
  - **Security Benefit**: Prevents credential theft from memory and eliminates reversible credential storage
  - **Category**: Security/Authentication
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="webproxyautodiscovery-disabled"></a>
### WebProxyAutoDiscovery-Disabled

- WinHttpAutoProxySvc Start: 4 (Disabled)
- AutoDetect: 0 (Disabled)
  - **Policy**: Disable Web Proxy Auto-Discovery (WPAD)
  - **Description**: Prevents the system from automatically discovering proxy settings
  - **Settings**:
    - WinHttpAutoProxySvc Start: 4 (Disabled)
    - AutoDetect: 0 (Disabled)
  - **Impact**: Prevents automatic proxy discovery and configuration
  - **Security Benefit**: Mitigates WPAD attacks and unauthorized proxy configuration
  - **Category**: Security/Network
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="wpad-computer-disabled"></a>
### WPAD-Computer-Disabled

- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DisableWpad = 1
  - **Policy**: Disable WPAD (Web Proxy Auto-Discovery) in the computer context
  - **Description**: Prevents the system from automatically discovering proxy settings via WPAD in the computer context
  - **Registry Setting**: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DisableWpad = 1
  - **Impact**: Prevents automatic proxy discovery and configuration at the computer level
  - **Security Benefit**: Mitigates WPAD attacks and unauthorized proxy configuration in the computer context
  - **Category**: Security/Network
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="wpad-user-disabled"></a>
### WPAD-User-Disabled

- HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AutoDetect = 0
  - **Policy**: Disable WPAD (Web Proxy Auto-Discovery) in the user context
  - **Description**: Prevents the system from automatically discovering proxy settings via WPAD in the user context
  - **Registry Setting**: HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AutoDetect = 0
  - **Impact**: Prevents automatic proxy discovery and configuration at the user level
  - **Security Benefit**: Mitigates WPAD attacks and unauthorized proxy configuration in the user context
  - **Category**: Security/Network
  - **Compatibility**: Windows Server 2008+ and Windows 7+

<a id="wscript-disabled"></a>
### WScript-Disabled

- HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled = 0
  - **Policy**: Disable Windows Script Host (WSH)
  - **Description**: Prevents execution of VBScript and JScript files via Windows Script Host
  - **Registry Setting**: HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled = 0
  - **Impact**: Blocks execution of .vbs and .js files via WSH (but not via other hosts like PowerShell or Internet Explorer)
  - **Security Benefit**: Reduces attack surface by preventing malicious script execution via WSH
  - **Category**: Security/Script Execution
  - **Compatibility**: Windows Server 2008+ and Windows 7+
  - **Note**: This does not prevent script execution via PowerShell or other script hosts
