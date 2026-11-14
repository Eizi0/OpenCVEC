#!/usr/bin/env bash
# Scénario de bout en bout contre le labo (lab/compose.yaml), à travers l'API réelle :
# liste blanche, assets, preuve de propriété, campagnes, verdicts attendus.
set -euo pipefail
API="${API:-http://127.0.0.1:8095}"
EMAIL="${EMAIL:-admin@lab.test}"
PASSWORD="${PASSWORD:-labo-opencvec-2026}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

call() { # méthode chemin [json]
  curl -sS -b "$JAR" -c "$JAR" -X "$1" -H 'X-OpenCVEC: 1' -H 'Content-Type: application/json' \
    ${3:+--data "$3"} "$API$2"
}

echo "· attente des cibles du labo"
for url in http://172.30.0.20:8983/solr/admin/cores http://172.30.0.21:8983/solr/admin/cores http://172.30.0.30:8080/ http://172.30.0.31:8080/ http://172.30.0.40/; do
  for _ in $(seq 1 60); do
    docker run --rm --network opencvec-lab_lab curlimages/curl:8.11.1 -sf -o /dev/null --max-time 3 "$url" && break
    sleep 3
  done
done

echo "· connexion"
call POST /api/login "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" >/dev/null
echo "· liste blanche 172.30.0.0/24"
call POST /api/allowlist '{"cidr":"172.30.0.0/24","reason":"labo OpenCVEC isolé","review_days":30}' >/dev/null || true

asset() { # hôte port → id
  local id
  id=$(call GET /api/assets | jq -r --arg h "$1" '.[] | select(.host==$h) | .id')
  if [ -z "$id" ]; then
    id=$(call POST /api/assets "{\"host\":\"$1\",\"proof_method\":\"allowlist\",\"scheme\":\"http\",\"port\":$2,\"tags\":[\"labo\"]}" | jq -r .id)
  fi
  local owned
  owned=$(call POST "/api/assets/$id/verify" | jq -r .owned)
  [ "$owned" = "true" ] || { echo "preuve refusée pour $1" >&2; exit 1; }
  echo "$id"
}

FAILED=0
declare -a LABELS CIDS EXPECTED
launch() { # libellé hôte port url checker verdict_attendu
  local id cid
  id=$(asset "$2" "$3")
  cid=$(call POST /api/campaigns "{\"asset_id\":$id,\"target_url\":\"$4\",\"checkers\":[\"$5\"]}" | jq -r .id)
  LABELS+=("$1"); CIDS+=("$cid"); EXPECTED+=("$6")
}

echo "· lancement des campagnes"
launch "Log4Shell / Solr 8.11.0"          172.30.0.20 8983 "http://172.30.0.20:8983/solr/admin/cores" log4shell  proved
launch "Log4Shell / Solr 8.11.2 corrigé"  172.30.0.21 8983 "http://172.30.0.21:8983/solr/admin/cores" log4shell  inconclusive
launch "Text4Shell / commons-text 1.9"    172.30.0.30 8080 "http://172.30.0.30:8080/"                 text4shell proved
launch "Text4Shell / 1.10.0 corrigé"      172.30.0.31 8080 "http://172.30.0.31:8080/"                 text4shell inconclusive
launch "PHP2Shell / PHP 8.3.20"           172.30.0.40 80   "http://172.30.0.40/"                      php2shell  probable

echo "· attente des verdicts (sans callback, le canari attend le délai réglé avant « non concluant »)"
for i in "${!CIDS[@]}"; do
  for _ in $(seq 1 300); do
    [ "$(call GET "/api/campaigns/${CIDS[$i]}" | jq -r .pending)" = "0" ] && break
    sleep 2
  done
  c=$(call GET "/api/campaigns/${CIDS[$i]}")
  verdict=$(jq -r '.checks[0].verdict' <<<"$c")
  summary=$(jq -r '.checks[0].summary' <<<"$c")
  if [ "$verdict" = "${EXPECTED[$i]}" ]; then
    printf '  OK    %-34s %-13s %s\n' "${LABELS[$i]}" "$verdict" "${summary:0:120}"
  else
    printf '  ÉCHEC %-34s %-13s (attendu %s) %s\n' "${LABELS[$i]}" "$verdict" "${EXPECTED[$i]}" "$summary"
    FAILED=1
  fi
done

echo "· refus attendu : cible hors périmètre"
out=$(call POST /api/campaigns "{\"asset_id\":$(asset 172.30.0.20 8983),\"target_url\":\"http://172.30.0.99/\",\"checkers\":[\"log4shell\"]}")
echo "  $out"
echo "· intégrité du journal d'audit : $(call GET /api/audit/verify)"
exit "$FAILED"
