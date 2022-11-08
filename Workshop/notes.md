# TODO
- make drawings for syscall params/mapping/etc

if you cannot connect with netcat:
Edit file `/etc/docker/daemon.json`

```json
{
	"dns": ["192.10.0.2", "8.8.8.8"]
}
```

then restart docker

```bash
sudo service docker restart
```