## Connect info
sudo wg-quick up wg0
ssh marton@mlsec
sudo wg-quick down wg0


## Start in docker
```bash
make build
docker-compose run server python3 -m mlsec.init_db # only needed the first time - it nukes the DB and (re)creates it
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
```

## Debug
In **vscode**:
- (start the docker instance from terminal)
- Run -> Start Debugging
