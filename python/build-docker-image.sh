#!/usr/bin/env bash

SCRIPT_DIR=$(dirname "$0")
ROOT_DIR="$SCRIPT_DIR/.."

IMAGE=${IMAGE:-minaombud/python-sample}
if [ -z "$VERSION" ]; then
  VERSION=$(sed -rn 's/^version\s*=\s*"([^"]+)"$/\1/p' <"$SCRIPT_DIR/pyproject.toml") || exit $?
fi

buildargs=()
[ -n "$SKIP_ITS" ] && buildargs+=(--build-arg "SKIP_ITS=$SKIP_ITS")
[ -n "$MINA_OMBUD_API_URL" ] && buildargs+=(--build-arg "MINA_OMBUD_API_URL=$MINA_OMBUD_API_URL")
[ -n "$MINA_OMBUD_API_TOKEN_URL" ] && buildargs+=(--build-arg "MINA_OMBUD_API_TOKEN_URL=$MINA_OMBUD_API_TOKEN_URL")
[ -n "$DOCKER_HUB_PROXY_REPOSITORY" ] && buildargs+=(--build-arg "DOCKER_HUB_PROXY_REPOSITORY=$DOCKER_HUB_PROXY_REPOSITORY")
if [[ "$DISABLE_SSL_TRUST" =~ true|1 ]]; then
  export PIP_TRUSTED_HOST="pypi.python.org pypi.org"
fi

while [ $# -gt 0 ]; do
  case "$1" in
    -latest | --latest) LATEST=y ;;
    -tag | --tag) TAG="$2"; shift ;;
    -image | --image) IMAGE="$2"; shift ;;
    --build-arg) buildargs+=(--build-arg "$2"); shift ;;
    *)
      echo "$0: invalid option: $1" >&2
      echo "Syntax: $0 [OPTIONS...]" >&2
      echo "  --latest        tag as latest" >&2
      echo "  --image NAME    set name of image (default: $IMAGE)">&2
      echo "  --tag TAG       set tag (default: $VERSION)" >&2
      echo
      exit 1
  esac
  shift
done

TAG=${TAG:-$VERSION}

if [ "$TAG" = latest ]; then
  LATEST=n
elif [ -z "$LATEST" ]; then
  branch=$(git rev-parse --abbrev-ref HEAD) || exit $?
  case "$branch" in
    master | main) LATEST=y ;;
    *) LATEST=n ;;
  esac
fi

cp -r "$ROOT_DIR/data" "$SCRIPT_DIR" || exit $?
trap 'rm -rf $SCRIPT_DIR/data' EXIT

for e in PIP_INDEX PIP_INDEX_URL PIP_TRUSTED_HOST; do
  v="${!e}"
  if [ -n "$v" ]; then
    echo "$e=$v"
    buildargs+=(--secret id="$e")
  fi
done

for e in PIP_CERT PIP_CONFIG_FILE; do
  v="${!e}"
  if [ -n "$v" ]; then
    echo "$e=$v"
    buildargs+=(--secret "id=$e,src=$v")
  fi
done

echo docker build --pull -t "$IMAGE:$TAG" "${buildargs[@]}" "$SCRIPT_DIR"
docker build --pull --progress plain -t "$IMAGE:$TAG" "${buildargs[@]}" "$SCRIPT_DIR" || exit $?
if [ "$LATEST" = y ]; then
  docker tag "$IMAGE:$TAG" "$IMAGE:latest" || exit $?
fi

echo "$IMAGE:$TAG"
