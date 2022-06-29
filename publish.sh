#!/bin/bash

docker login
docker build -t scan-result .
docker tag scan-result mawinkler/scan-result:latest
docker push mawinkler/scan-result:latest