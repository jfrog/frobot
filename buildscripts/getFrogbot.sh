#!/bin/bash

FROGBOT_OS="na"
FILE_NAME="na"
VERSION="[RELEASE]"
PLATFORM_URL="https://releases.jfrog.io"
REPOSITORY="frogbot"

setFrogbotVersion() {
  if [ $# -eq 1 ]
  then
      VERSION=$1
      echo "Downloading version $VERSION of Frogbot..."
  else
      echo "Downloading the latest version of Frogbot..."
  fi
}

setFrogbotRemoteRepositoryIfNeeded() {
  if [ -n "${JF_RELEASES_REPO}" ]
  then
    PLATFORM_URL="${JF_URL%%/}"
    REPOSITORY="$JF_RELEASES_REPO"
  fi
}

setWindowsProperties() {
  FROGBOT_OS="windows"
  URL="${PLATFORM_URL}/artifactory/${REPOSITORY}/v2/${VERSION}/frogbot-windows-amd64/frogbot.exe"
  FILE_NAME="frogbot.exe"
}

setMacProperties() {
  FROGBOT_OS="mac"
  URL="${PLATFORM_URL}/artifactory/${REPOSITORY}/v2/${VERSION}/frogbot-mac-386/frogbot"
  FILE_NAME="frogbot"
}

setLinuxProperties() {
  FROGBOT_OS="linux"
  MACHINE_TYPE="$(uname -m)"
  case $MACHINE_TYPE in
      i386 | i486 | i586 | i686 | i786 | x86)
          ARCH="386"
          ;;
      amd64 | x86_64 | x64)
          ARCH="amd64"
          ;;
      arm | armv7l)
          ARCH="arm"
          ;;
      aarch64)
          ARCH="arm64"
          ;;
      s390x)
          ARCH="s390x"
          ;;
      ppc64)
         ARCH="ppc64"
         ;;
      ppc64le)
         ARCH="ppc64le"
         ;;
      *)
          echo "Unknown machine type: $MACHINE_TYPE"
          exit 1
          ;;
  esac
  URL="${PLATFORM_URL}/artifactory/${REPOSITORY}/v2/${VERSION}/frogbot-${FROGBOT_OS}-${ARCH}/frogbot"
  FILE_NAME="frogbot"
}

setFrogbotDownloadProperties() {
  if echo "${OSTYPE}" | grep -q msys; then
    setWindowsProperties
  elif echo "${OSTYPE}" | grep -q darwin; then
    setMacProperties
  else
    setLinuxProperties
  fi
}

setPermissions() {
  chmod u+x "${FILE_NAME}"
}

echoGreetings() {
  echo "Frogbot downloaded successfully!"
}

getDownloadCommand() {
  if [ -n "${JF_RELEASES_REPO}" ]; then
      if [ -n "${JF_ACCESS_TOKEN}" ]; then
        curl -fLg -H "Authorization:Bearer ${JF_ACCESS_TOKEN}" -X GET "${URL}" -o "${FILE_NAME}"
      else
        curl -fLg -u "${JF_USER}:${JF_PASSWORD}" -X GET "${URL}" -o "${FILE_NAME}"
      fi
    else
      curl -fLg -X GET "${URL}" -o "${FILE_NAME}"
    fi
}

download() {
  getDownloadCommand && setPermissions && echoGreetings
}

setFrogbotVersion "$@"
setFrogbotRemoteRepositoryIfNeeded
setFrogbotDownloadProperties
download
