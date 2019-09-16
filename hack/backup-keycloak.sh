#! /bin/bash
set -e -o pipefail
cd $(git rev-parse --show-toplevel)
echo "# Backing up keycloak database as a SQL text dump"
dump=keycloak-$(date +%Y%m%d).sql
docker-compose exec --user=postgres postgres pg_dumpall --clean --file=/tmp/${dump}
cd hack
container=$(docker ps -q --filter='name=postgres')
echo "Now retrieving dump file from: ${container} into ${dump}..."
docker cp ${container}:/tmp/${dump} .
