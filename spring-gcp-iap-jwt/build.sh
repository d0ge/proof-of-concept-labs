#!/bin/bash
docker rm -f spring-gcp-poc
docker build -t spring-gcp-poc .
docker run --name=spring-gcp-poc --rm -p8008:8008 -it spring-gcp-poc