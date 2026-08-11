#!/usr/bin/env bash
set -euo pipefail

container_name="veloauth-postgres-it-$$"
database_name="veloauth_it"
database_user="veloauth_it"
database_password="veloauth_it_password"

cleanup() {
  docker stop "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --rm --detach \
  --name "${container_name}" \
  --env "POSTGRES_DB=${database_name}" \
  --env "POSTGRES_USER=${database_user}" \
  --env "POSTGRES_PASSWORD=${database_password}" \
  --publish 127.0.0.1::5432 \
  --health-cmd="pg_isready -U ${database_user} -d ${database_name}" \
  --health-interval=1s \
  --health-timeout=5s \
  --health-retries=30 \
  postgres:17-alpine >/dev/null

for _ in $(seq 1 45); do
  health_status="$(docker inspect --format '{{.State.Health.Status}}' "${container_name}")"
  if [[ "${health_status}" == "healthy" ]]; then
    break
  fi
  if [[ "${health_status}" == "unhealthy" ]]; then
    docker logs "${container_name}"
    exit 1
  fi
  sleep 1
done

if [[ "$(docker inspect --format '{{.State.Health.Status}}' "${container_name}")" != "healthy" ]]; then
  docker logs "${container_name}"
  exit 1
fi

published_address="$(docker port "${container_name}" 5432/tcp)"
published_port="${published_address##*:}"
postgres_url="jdbc:postgresql://127.0.0.1:${published_port}/${database_name}"

if command -v mvnd >/dev/null 2>&1; then
  maven_command=(mvnd)
elif [[ -x ./mvnw ]]; then
  maven_command=(./mvnw)
else
  maven_command=(mvn)
fi

"${maven_command[@]}" test \
  -Dtest=PremiumUuidDaoPostgreSqlIT,JdbcAuthDaoDatabaseIT,DatabaseMigrationDatabaseIT \
  -Dveloauth.postgres.url="${postgres_url}" \
  -Dveloauth.postgres.user="${database_user}" \
  -Dveloauth.postgres.password="${database_password}" \
  -Dveloauth.database.type="POSTGRESQL" \
  -Dveloauth.database.url="${postgres_url}?sslmode=disable" \
  -Dveloauth.database.user="${database_user}" \
  -Dveloauth.database.password="${database_password}"
