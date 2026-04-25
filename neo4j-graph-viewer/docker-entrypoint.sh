#!/bin/sh
set -e

HTTP_URL="${NEO4J_HTTP_URL:-http://localhost:7474}"
USERNAME="${NEO4J_USERNAME:-neo4j}"
PASSWORD="${NEO4J_PASSWORD:-change-this-neo4j-password}"

cat > /usr/share/nginx/html/config.js << JSEOF
window.NEO4J_CONFIG = {
    httpUrl:  "${HTTP_URL}",
    username: "${USERNAME}",
    password: "${PASSWORD}"
};
JSEOF

exec "$@"
