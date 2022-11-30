
# Building the controller
```bash
source scripts/activate.sh

gn gen out/host

ninja -C out/host
```

## Installing whls:
```bash
cd /connectedhomeip/out/host/controller/python
pip3 install ./*.whl
```
