#!/bin/sh

set -e

# Environment check
printf "\033[33;1mNote: COVERITY_SCAN_PROJECT_NAME and COVERITY_SCAN_TOKEN are available on Project Settings page on scan.coverity.com\033[0m\n"
[ -z "$COVERITY_SCAN_PROJECT_NAME" ] && echo "ERROR: COVERITY_SCAN_PROJECT_NAME must be set" && exit 1
#[ -z "$COVERITY_SCAN_NOTIFICATION_EMAIL" ] && echo "ERROR: COVERITY_SCAN_NOTIFICATION_EMAIL must be set" && exit 1
[ -z "$COVERITY_SCAN_BUILD_COMMAND" ] && echo "ERROR: COVERITY_SCAN_BUILD_COMMAND must be set" && exit 1
[ -z "$COVERITY_SCAN_TOKEN" ] && echo "ERROR: COVERITY_SCAN_TOKEN must be set" && exit 1

PLATFORM=$(uname)
TOOL_ARCHIVE=/tmp/cov-analysis-${PLATFORM}.tgz
TOOL_URL=https://scan.coverity.com/download/cxx/${PLATFORM}
TOOL_BASE=/tmp/coverity-scan-analysis
UPLOAD_URL="https://scan.coverity.com/builds"
SCAN_URL="https://scan.coverity.com"

# Verify upload is permitted
AUTH_RES=$(curl -s --form project="$COVERITY_SCAN_PROJECT_NAME" --form token="$COVERITY_SCAN_TOKEN" $SCAN_URL/api/upload_permitted)
if [ "$AUTH_RES" = "Access denied" ]; then
  printf "\033[33;1mCoverity Scan API access denied. Check COVERITY_SCAN_PROJECT_NAME and COVERITY_SCAN_TOKEN.\033[0m\n"
  exit 1
else
  AUTH=$(echo "$AUTH_RES" | ruby -e "require 'rubygems'; require 'json'; puts JSON[STDIN.read]['upload_permitted']")
  if [ "$AUTH" = "true" ]; then
    printf "\033[33;1mCoverity Scan analysis authorized per quota.\033[0m\n"
  else
    WHEN=$(echo "$AUTH_RES" | ruby -e "require 'rubygems'; require 'json'; puts JSON[STDIN.read]['next_upload_permitted_at']")
    printf "\033[33;1mCoverity Scan analysis NOT authorized until %s.\033[0m\n" "$WHEN"
    exit 0
  fi
fi

if [ ! -d $TOOL_BASE ]; then
  # Download Coverity Scan Analysis Tool
  if [ ! -e "$TOOL_ARCHIVE" ]; then
    printf "\033[33;1mDownloading Coverity Scan Analysis Tool...\033[0m\n"
    wget -nv -O "$TOOL_ARCHIVE" "$TOOL_URL" --post-data "project=$COVERITY_SCAN_PROJECT_NAME&token=$COVERITY_SCAN_TOKEN"
  fi

  # Extract Coverity Scan Analysis Tool
  printf "\033[33;1mExtracting Coverity Scan Analysis Tool...\033[0m\n"
  mkdir -p $TOOL_BASE
  tar xzf "$TOOL_ARCHIVE" -C "$TOOL_BASE"
fi

TOOL_DIR=$(find $TOOL_BASE -type d -name 'cov-analysis*')
export PATH=$TOOL_DIR/bin:$PATH

# Build
printf "\033[33;1mRunning Coverity Scan Analysis Tool...\033[0m\n"
COV_BUILD_OPTIONS=""
#COV_BUILD_OPTIONS="--return-emit-failures 8 --parse-error-threshold 85"
RESULTS_DIR="cov-int"
eval "${COVERITY_SCAN_BUILD_COMMAND_PREPEND}"
# Do not quote COV_BUILD_OPTIONS so it collapses when it is empty and expands
# when it is not.
# shellcheck disable=SC2086
COVERITY_UNSUPPORTED=1 cov-build --dir "$RESULTS_DIR" $COV_BUILD_OPTIONS "$COVERITY_SCAN_BUILD_COMMAND"
cov-import-scm --dir $RESULTS_DIR --scm git --log $RESULTS_DIR/scm_log.txt 2>&1

# Upload results
printf "\033[33;1mTarring Coverity Scan Analysis results...\033[0m\n"
RESULTS_ARCHIVE=analysis-results.tgz
tar czf $RESULTS_ARCHIVE $RESULTS_DIR
SHA=$(git rev-parse --short HEAD)
VERSION_SHA=$(cat VERSION)#$SHA

# Verify Coverity Scan script test mode
if [ "${coverity_scan_script_test_mode:-false}" = true ]; then
  printf "\033[33;1mCoverity Scan configured in script test mode. Exit.\033[0m\n"
  exit 0
fi

printf "\033[33;1mUploading Coverity Scan Analysis results...\033[0m\n"
response=$(curl \
  --silent --write-out "\n%{http_code}\n" \
  --form project="$COVERITY_SCAN_PROJECT_NAME" \
  --form token="$COVERITY_SCAN_TOKEN" \
  --form email=blackhole@blackhole.io \
  --form file=@$RESULTS_ARCHIVE \
  --form version="$SHA" \
  --form description="$VERSION_SHA" \
  $UPLOAD_URL)
status_code=$(echo "$response" | sed -n '$p')
if [ "$status_code" != "200" ] && [ "$status_code" != "201" ]; then
  TEXT=$(echo "$response" | sed '$d')
  printf "\033[33;1mCoverity Scan upload failed with HTTP status code '%s': %s.\033[0m\n" "$status_code" "$TEXT"
  exit 1
fi
