#!/bin/bash

docker rm vaultplg --force
docker network rm vaultplg
rm -rf $(pwd)/vaultplg
