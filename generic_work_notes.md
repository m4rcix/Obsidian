## TODO
- upgrade kirale border gateway ✅
- flash onto SD card ✅
- change ip address into 192.168.45/24 ✅
- make sure Lenovo Desktop in office doesn't turn off ✅

## Matter Lab access

192.168.45.6 from budapest office
10.4.160.20:2222 from vpn

From Local wifi

ssh 192.168.45.6 -l mattertest -X -Y

From VPN 

ssh 10.4.160.20 -p 2222 -l mattertest -X -Y
rdesktop -u mattertest 10.4.160.20