#!/usr/bin/env bash
set -euo pipefail

container_name="veloauth-mysql-it-$$"
database_name="veloauth_it"
database_user="veloauth_it"
database_password="veloauth_it_password"
root_password="veloauth_it_root_password"

cleanup() {
  docker stop "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --rm --detach \
  --name "${container_name}" \
  --env "MYSQL_DATABASE=${database_name}" \
  --env "MYSQL_USER=${database_user}" \
  --env "MYSQL_PASSWORD=${database_password}" \
  --env "MYSQL_ROOT_PASSWORD=${root_password}" \
  --publish 127.0.0.1::3306 \
  --health-cmd="mysqladmin ping -h 127.0.0.1 -u${database_user} -p${database_password} --silent" \
  --health-interval=2s \
  --health-timeout=5s \
  --health-retries=45 \
  mysql:8.4 >/dev/null

for _ in $(seq 1 60); do
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

published_address="$(docker port "${container_name}" 3306/tcp)"
published_port="${published_address##*:}"
mysql_url="jdbc:mysql://127.0.0.1:${published_port}/${database_name}?useSSL=false&serverTimezone=UTC"

if command -v mvnd >/dev/null 2>&1; then
  maven_command=(mvnd)
elif [[ -x ./mvnw ]]; then
  maven_command=(./mvnw)
else
  maven_command=(mvn)
fi

"${maven_command[@]}" test \
  -Dtest=JdbcAuthDaoDatabaseIT,DatabaseMigrationDatabaseIT \
  -Dveloauth.database.type="MYSQL" \
  -Dveloauth.database.url="${mysql_url}" \
  -Dveloauth.database.user="${database_user}" \
  -Dveloauth.database.password="${database_password}"
