
## Matter Lab access

192.168.45.6 from budapest office
10.4.160.20:2222 from vpn

From Local wifi

ssh 192.168.45.6 -l mattertest -X -Y

From VPN 

```bash
sudo ifconfig gpd0 mtu 1200 # if ssh does not work
```

ssh 10.4.160.20 -p 2222 -l mattertest -X -Y
rdesktop -u mattertest 10.4.160.20

## szakmai gyakorlat
- Egyetemen febr. 28. indul a kepzes (1 honap csuszas futes miatt)
- Szakmai gyakorlat (8 het) kerdeses
- Papirozasi problemak (Egyetemi reszrol)
- ZOLI :

# Matter

- chip-repl python interfacing
- build and flash esp
- commisioning