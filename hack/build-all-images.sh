#! /bin/bash
set -e -o pipefail
cd "$(git rev-parse --show-toplevel)"
cd build
docker build -f Dockerfile-builder -t keycloak-builder .
docker build -f Dockerfile -t keycloak-flaminem:latest .
