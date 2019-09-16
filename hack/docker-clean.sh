#!/bin/bash
cd "$(git rev-parse --show-toplevel)"
# docker network prune --force
# docker container prune --force
# docker volume prune
docker-compose down --rmi local --volumes --remove-orphans
