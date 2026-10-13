#!/usr/bin/env bash
# Elodea in one minute: an agent's tool calls are allowed, denied, or held for
# a human; a reviewer approves; Elodea re-checks policy and replays the exact
# request once; the audit ledger shows every step and verifies.
#
# Runs against the local Docker Compose stack:
#   docker compose up -d --build --wait
#   bash scripts/demo.sh
#
# It doubles as a smoke test: it exits non-zero as soon as a step does not
# behave as described. Needs curl and jq.
#
#   ELODEA_URL             proxy URL (default http://localhost:8080)
#   ELODEA_AGENT_TOKEN     agent token (default: the compose dev token)
#   ELODEA_REVIEWER_TOKEN  reviewer token (default: the compose dev token)
#   DEMO_PAUSE             seconds between steps (default 1.5; 0 for CI)
set -euo pipefail

URL="${ELODEA_URL:-http://localhost:8080}"
AGENT_TOKEN="${ELODEA_AGENT_TOKEN:-sk_agent_local_000000000000}"
REVIEWER_TOKEN="${ELODEA_REVIEWER_TOKEN:-sk_reviewer_local_00000000}"
PAUSE="${DEMO_PAUSE:-1.5}"

for cmd in curl jq; do
  command -v "$cmd" >/dev/null || { echo "demo.sh needs $cmd on PATH" >&2; exit 1; }
done

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  bold=$'\e[1m' dim=$'\e[2m' red=$'\e[31m' green=$'\e[32m' yellow=$'\e[33m' cyan=$'\e[36m' reset=$'\e[0m'
else
  bold='' dim='' red='' green='' yellow='' cyan='' reset=''
fi

step() { sleep "$PAUSE"; printf '\n%s%s%s\n' "$bold" "$1" "$reset"; }
note() { printf '  %s%s%s\n' "$dim" "$1" "$reset"; }
ok()   { printf '  %s✓ %s%s\n' "$green" "$1" "$reset"; }
held() { printf '  %s… %s%s\n' "$yellow" "$1" "$reset"; }
no()   { printf '  %s✗ %s%s\n' "$red" "$1" "$reset"; }
fail() { printf '\n%sdemo failed: %s%s\n' "$red" "$1" "$reset" >&2; exit 1; }

# request METHOD PATH TOKEN [BODY]: sets STATUS and BODY.
request() {
  local args=(-sS -X "$1" "$URL$2" -H "Authorization: Bearer $3" -H 'Content-Type: application/json' -w $'\n%{http_code}')
  if [[ $# -ge 4 ]]; then args+=(-d "$4"); fi
  local out
  out=$(curl "${args[@]}") || fail "could not reach Elodea at $URL"
  STATUS=${out##*$'\n'}
  BODY=${out%$'\n'*}
}

# call_tool NAME ARGUMENTS_JSON: the agent sends an MCP tools/call through Elodea.
call_tool() {
  printf '  %sagent →%s %s %s\n' "$cyan" "$reset" "$1" "$2"
  request POST / "$AGENT_TOKEN" "$(jq -cn --arg name "$1" --argjson args "$2" \
    '{jsonrpc: "2.0", id: 1, method: "tools/call", params: {name: $name, arguments: $args}}')"
}

expect_status() {
  [[ "$STATUS" == "$1" ]] || fail "expected HTTP $1, got $STATUS: $BODY"
}

field() { jq -r "$1" <<<"$BODY" 2>/dev/null || echo "?"; }

printf '%sElodea: an AI agent moving money, governed by policy%s\n' "$bold" "$reset"
note "Policy: refunds up to \$1,000 run alone, larger ones wait for a human, sanctioned wires are blocked."

for _ in $(seq 1 30); do
  curl -fsS "$URL/readyz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$URL/readyz" >/dev/null 2>&1 || fail "Elodea is not ready at $URL. Start it with: docker compose up -d --build --wait"

step "1. A \$250 refund, inside the autonomous limit"
call_tool stripe.charge.refund '{"charge": "ch_1001", "amount": 250}'
expect_status 200
ok "allowed: forwarded to the payments API"
note "The API saw X-Elodea-Agent: $(field '.headers["x-elodea-agent"] // "?"'), set by Elodea, not the agent."

step "2. A wire to a sanctioned jurisdiction"
call_tool swift.wire.initiate '{"amount": 5000, "jurisdiction": "OFAC_FLAGGED"}'
expect_status 403
no "denied: $(field .explanation)"

step "3. A \$1,500 refund, over the limit"
call_tool stripe.charge.refund '{"charge": "ch_1002", "amount": 1500}'
expect_status 202
QID=$(field .quarantine_id)
[[ -n "$QID" && "$QID" != "?" && "$QID" != "null" ]] || fail "no quarantine_id in: $BODY"
SHORT_ID="${QID:0:8}"
held "held for human review (#$SHORT_ID). Nothing has reached the payments API."

step "4. The agent tries to approve its own refund"
request POST "/api/v1/quarantine/$QID/approve" "$AGENT_TOKEN"
expect_status 403
no "rejected: $(field .error)"
note "Agents and reviewers are separate trust domains; an agent token can never approve."

step "5. A reviewer opens the approval queue"
request GET "/api/v1/quarantine?status=pending" "$REVIEWER_TOKEN"
expect_status 200
ITEM=$(jq -r --arg id "$QID" '.[] | select(.ID == $id) | "#\(.ID[0:8])  \(.ToolName)  rule: \(.PolicyRule)"' <<<"$BODY")
[[ -n "$ITEM" ]] || fail "quarantine #$SHORT_ID is not in the pending queue"
note "$ITEM"

step "6. The reviewer approves"
request POST "/api/v1/quarantine/$QID/approve" "$REVIEWER_TOKEN"
expect_status 200
ok "approved, recorded under the reviewer's identity"

step "7. Elodea re-checks current policy, then replays the exact request once"
replayed=false
for _ in $(seq 1 30); do
  request GET "/api/v1/quarantine?status=replayed" "$REVIEWER_TOKEN"
  if jq -e --arg id "$QID" 'any(.[]; .ID == $id)' <<<"$BODY" >/dev/null; then
    replayed=true
    break
  fi
  request GET "/api/v1/quarantine?status=replay_failed" "$REVIEWER_TOKEN"
  if jq -e --arg id "$QID" 'any(.[]; .ID == $id)' <<<"$BODY" >/dev/null; then
    fail "replay of #$SHORT_ID failed; see: docker compose logs proxy"
  fi
  sleep 1
done
[[ "$replayed" == true ]] || fail "replay of #$SHORT_ID did not finish within 30s"
ok "replayed once, with a stable Idempotency-Key so a retry can never run it twice"

step "8. The audit ledger, oldest first"
request GET "/api/v1/ledger?limit=6" "$REVIEWER_TOKEN"
expect_status 200
jq -r '
  def pad(n): tostring | . + ([range(0; n - length)] | map(" ") | join(""));
  reverse | .[] | "  #\(.seq_num | pad(4)) \(.decision | pad(19)) \(.tool | pad(22)) \(.hash[0:12])…"
' <<<"$BODY"

step "9. Verify the hash chain"
request GET /api/v1/ledger/verify "$REVIEWER_TOKEN"
expect_status 200
jq -e '.valid' <<<"$BODY" >/dev/null || fail "ledger verification failed: $BODY"
ok "chain valid: $(field .entries) entries, head $(field '.head_hash[0:12]')…"
note "Anchor the head hash outside the database to prove later that nothing was rewritten."

printf '\n%sDone.%s Every call was decided by policy and written to the ledger before anything ran.\n' "$bold" "$reset"
