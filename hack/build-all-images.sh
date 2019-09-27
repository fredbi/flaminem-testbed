#! /bin/bash
set -e -o pipefail
cd "$(git rev-parse --show-toplevel)"
cd build/server
docker build -f Dockerfile-builder -t keycloak-builder .
docker build -f Dockerfile --no-cache -t keycloak-flaminem:latest .
