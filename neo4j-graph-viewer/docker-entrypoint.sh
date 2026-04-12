#!/bin/sh
set -e

BOLT_URL="${NEO4J_BOLT_URL:-bolt://localhost:7687}"
USERNAME="${NEO4J_USERNAME:-neo4j}"
PASSWORD="${NEO4J_PASSWORD:-neo4j123}"

cat > /usr/share/nginx/html/config.js << JSEOF
window.NEO4J_CONFIG = {
    boltUrl: "${BOLT_URL}",
    username: "${USERNAME}",
    password: "${PASSWORD}"
};
JSEOF

exec "$@"
