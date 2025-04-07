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

# set up dependencies
sudo apt-get update || true
sudo apt-get update
sudo apt-get -y upgrade
sudo apt-get install -y qemu-kvm jq docker.io docker-buildx make \
     clang cpp gcc zlib1g-dev libaio-dev libcap-dev libelf-dev \
     liburing-dev net-tools netcat-traditional socat \
     iptables software-properties-common netcat-openbsd iproute2

VERSION_GO_CONTAINERREGISTRY=v0.19.1
URL="https://github.com/google/go-containerregistry/releases/download/$VERSION_GO_CONTAINERREGISTRY/go-containerregistry_Linux_arm64.tar.gz"
curl -fSL $URL | sudo tar -xz -C /usr/local/bin crane
crane version

# set up SSH for LVH
sudo ufw allow OpenSSH
sudo ufw --force enable
sudo sed -i "s/.*PasswordAuthentication .*/PasswordAuthentication no/g" /etc/ssh/sshd_config
sudo sed -i "s/.*PubkeyAuthentication .*/PubkeyAuthentication yes/g" /etc/ssh/sshd_config
sudo systemctl restart ssh

# prepare multi-runners
mkdir -p multi-runners && cd multi-runners
VERSION_MULTI_RUNNERS=v1.2.0
curl -L -o multi-runners.tar.gz https://github.com/vbem/multi-runners/archive/refs/tags/$VERSION_MULTI_RUNNERS.tar.gz
tar xzf ./multi-runners.tar.gz --strip-components=1

# get GH token for runners provisioning
GITHUB_RUNNERS_TOKEN=$(get_github_runners_token)

# create runners
sudo tee .env <<EOF
MR_RELEASE_URL='https://github.com/actions/runner/releases/download/v2.321.0/actions-runner-linux-arm64-2.321.0.tar.gz'
EOF
for (( i=1; i<=$GITHUB_RUNNERS_COUNT; i++ ))
do
  ./mr.bash add --org $GITHUB_ORG --group $GITHUB_GROUP --labels $GITHUB_LABELS --user runner-$i --token $GITHUB_RUNNERS_TOKEN
done

# prepare directories for LVH
mkdir -p /home/runners && chown :runners /home/runners && chmod 774 /home/runners

