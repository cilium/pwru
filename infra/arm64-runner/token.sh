#!/bin/bash

GITHUB_API_SERVER="api.github.com"

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

GITHUB_RUNNERS_TOKEN=$(get_github_runners_token)
echo "$GITHUB_RUNNERS_TOKEN"

