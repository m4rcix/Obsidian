# With Hydra
```bash
hydra -L <wordlist> **or** -l <user> -P<password list>  
<targeti_p> http-post-form "loginURL:username=^USER^&password=^PASS^&Login=Login:Login failed"
```
