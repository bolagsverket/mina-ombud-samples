#!/bin/sh

SCRIPT_DIR=$(dirname "$0")
ROOT_DIR="$SCRIPT_DIR/.."

IMAGE=${IMAGE:-minaombud/python-sample}
PUSH=${PUSH:-n}
[ "$PUSH" = true ] && PUSH=y

DISABLE_SSL_TRUST=${DISABLE_SSL_TRUST:-0}
VERSION=$(sed -rn 's/^version\s*=\s*"([^"]+)"$/\1/p' <"$SCRIPT_DIR/pyproject.toml") || exit $?

while [ $# -gt 0 ]; do
  case "$1" in
    -latest | --latest) LATEST=y ;;
    -push | --push) PUSH=y ;;
    -tag | --tag) TAG="$2"; shift ;;
    -image | --image) IMAGE="$2"; shift ;;
    -registry | --registry) REGISTRY="$2"; shift ;;
    *)
      echo "$0: invalid option: $1" >&2
      echo "Syntax: $0 [OPTIONS...]" >&2
      echo "  --latest        tag as latest" >&2
      echo "  --push          tag and push image to registry" >&2
      echo "  --image NAME    set name of image (default: $IMAGE)">&2
      echo "  --tag TAG       set tag (default: $VERSION)" >&2
      echo "  --registry HOST set registry for push" >&2
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
cleanup="$SCRIPT_DIR/data"
trap 'rm -rf $cleanup' EXIT

docker build --pull -t "$IMAGE:$TAG" --build-arg "DISABLE_SSL_TRUST=$DISABLE_SSL_TRUST" "$SCRIPT_DIR"
if [ "$LATEST" = y ]; then
  docker tag "$IMAGE:$TAG" "$IMAGE:latest" || exit $?
fi

tag_and_push() {
  echo "Pushing image $IMAGE:$1..."
  registry=${REGISTRY?-missing}
  docker tag "$IMAGE:$TAG" "$registry/$IMAGE:$1" \
    && docker push "$registry/$IMAGE:$1" \
    || exit $?
}

if [ -n "$REGISTRY_CREDENTIALS_USR" ]; then
  tmp_base="${WORKSPACE:-$ROOT_DIR}"
  export DOCKER_CONFIG=$(mktemp -d -p "$tmp_base") || exit $?
  cleanup="$cleanup $DOCKER_CONFIG"
  echo "$REGISTRY_CREDENTIALS_PSW" | docker login -u "$REGISTRY_CREDENTIALS_USR" --password-stdin $REGISTRY
fi

if [ "$PUSH" = y ]; then
  tag_and_push "$TAG"
  [ "$LATEST" = y ] && tag_and_push latest
fi

echo "$IMAGE:$TAG"
