#!/bin/bash

echo "$GHCR_PASSWORD"   | docker login ghcr.io -u "$GHCR_USERNAME"   --password-stdin

export GHCR_ORG="ocsp-manager"
export GHCR_PROJECT="ocsp-manager"
export GHCR_REPO="ghcr.io/${GHCR_ORG}/${GHCR_PROJECT}"


if [[ $GITHUB_REF == refs/tags/* ]]; then
  export GIT_TAG=${GITHUB_REF#refs/tags/}
else
  export GIT_BRANCH=${GITHUB_REF#refs/heads/}
fi

if [[ -n "${GIT_TAG}" ]]; then
  docker buildx build --progress plain --pull --push --platform "${DOCKER_BUILD_PLATFORM}" -t ${GHCR_REPO}:${GIT_TAG} \
  --label "org.opencontainers.image.created=$(date -u --iso-8601=seconds)" \
  --label "org.opencontainers.image.revision=${GITHUB_SHA}" \
  .
elif [[ -n "${GIT_BRANCH}" ]]; then
  if [[ "${GIT_BRANCH}" == "master" || "${GIT_BRANCH}" == "main" ]]; then
    docker buildx build --progress plain --pull --push --platform "${DOCKER_BUILD_PLATFORM}" -t ${GHCR_REPO}:latest \
    --label "org.opencontainers.image.created=$(date -u --iso-8601=seconds)" \
    --label "org.opencontainers.image.revision=${GITHUB_SHA}" \
    .
  else
    docker buildx build --progress plain --pull --push --platform "${DOCKER_BUILD_PLATFORM}" -t ${GHCR_REPO}:${GIT_BRANCH} \
    --label "org.opencontainers.image.created=$(date -u --iso-8601=seconds)" \
    --label "org.opencontainers.image.revision=${GITHUB_SHA}" \
    .
  fi
else
  :
fi
