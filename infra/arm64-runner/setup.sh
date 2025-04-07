#!/bin/bash

set -e

GITHUB_API_SERVER="api.github.com"
# the following lines will be replaced by Terraform
GITHUB_APP_ID="{GITHUB_APP_ID}"
GITHUB_APP_INSTALL_ID="{GITHUB_APP_INSTALL_ID}"
GITHUB_APP_PEM="{GITHUB_APP_PEM}"
GITHUB_ORG="{GITHUB_ORG}"
GITHUB_GROUP="{GITHUB_GROUP}"
GITHUB_LABELS="{GITHUB_LABELS}"
GITHUB_RUNNERS_COUNT="{GITHUB_RUNNERS_COUNT}"

get_github_runners_token() {
  NOW=$( date +%s )
  IAT=$(($NOW  - 60))
  EXP=$(($NOW + 540))
  HEADER_RAW='{"alg":"RS256"}'
  HEADER=$( echo -n "$HEADER_RAW" | openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n' )
  PAYLOAD_RAW='{"iat":'"$IAT"',"exp":'"$EXP"',"iss":'"$GITHUB_APP_ID"'}'
  PAYLOAD=$( echo -n "$PAYLOAD_RAW" | openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n' )
  HEADER_PAYLOAD="$HEADER"."$PAYLOAD"

  # Making a tmp directory here because /bin/sh doesn't support process redirection <()
  tmp_dir=/tmp/github_app_tmp
  mkdir "$tmp_dir"
  echo -n "$GITHUB_APP_PEM" > "$tmp_dir/github.pem"
  echo -n "$HEADER_PAYLOAD" > "$tmp_dir/header"
  SIGNATURE=$( openssl dgst -sha256 -sign "$tmp_dir/github.pem" "$tmp_dir/header" | openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n' )
  rm -rf "$tmp_dir"

  JWT="$HEADER_PAYLOAD"."$SIGNATURE"
  INSTALL_URL="https://$GITHUB_API_SERVER/app/installations/$GITHUB_APP_INSTALL_ID/access_tokens"
  INSTALL_TOKEN_PAYLOAD=$(curl -sSfLX POST -H "Authorization: Bearer $JWT" -H "Accept: application/vnd.github.v3+json" "$INSTALL_URL")
  INSTALL_TOKEN=$(echo $INSTALL_TOKEN_PAYLOAD | jq .token --raw-output)

  token_url="https://$GITHUB_API_SERVER/orgs/$GITHUB_ORG/actions/runners/registration-token"
  payload=$(curl -sSfLX POST -H "Authorization: token $INSTALL_TOKEN" $token_url)

  RUNNER_TOKEN=$(echo $payload | jq .token --raw-output)
  echo "$RUNNER_TOKEN"
}

# get GH token for runners provisioning
GITHUB_RUNNERS_TOKEN=$(get_github_runners_token)

cd /opt/multi-runners

for (( i=1; i<=$GITHUB_RUNNERS_COUNT; i++ ))
do
  ./mr.bash add --org $GITHUB_ORG --group $GITHUB_GROUP --labels $GITHUB_LABELS --user runner-$i --token $GITHUB_RUNNERS_TOKEN
done
