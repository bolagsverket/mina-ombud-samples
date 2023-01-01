#!/bin/sh

SCRIPT_DIR=$(dirname "$0")
ROOT_DIR="$SCRIPT_DIR/.."

VERSION=$(sed -rn 's/^version\s*=\s*"([^"]+)"$/\1/p' <"$SCRIPT_DIR/pyproject.toml") || exit $?
OVERWRITE=${OVERWRITE:-n}
PUSH=${PUSH:-n}
[ "$PUSH" = true ] && PUSH=y
[ "$OVERWRITE" = true ] && OVERWRITE=y

while [ $# -gt 0 ]; do
  case "$1" in
    -d | --build-dir) HELM_BUILD_DIR="$2" shift ;;
    -push | --push) PUSH=y ;;
    -version | --version) VERSION="$2" shift ;;
    -tag | --tag) TAG="$2" shift ;;
    -repo | --repo) CHART_REPO="$2" shift ;;
    -upload-url | --upload-url) CHART_REPO_UPLOAD_URL="$2" shift ;;
    -overwrite | --overwrite) OVERWRITE=y ;;
    *)
      echo "$0: invalid option: $1" >&2
      echo "Syntax: $0 [OPTIONS...]" >&2
      echo "  -d, --build-dir PATH  chart output directory" >&2
      echo "  --push                push chart to registry" >&2
      echo "  --overwrite           overwrite chart" >&2
      echo "  --version VER         set chart version (default: $VERSION)" >&2
      echo "  --tag TAG             set app version (default: $VERSION)" >&2
      echo "  --repo HOST/URL       set chart repo host/url" >&2
      echo "  --upload-url URL      set chart repo upload URL" >&2
      echo
      exit 1
      ;;
  esac
  shift
done

TAG=${TAG:-$VERSION}

HELM_BUILD_DIR=${HELM_BUILD_DIR:-.}

tgz="mina-ombud-python-server-$VERSION.tgz"
helm package "$SCRIPT_DIR/helm" --version "$VERSION" --app-version "$TAG" -d "$HELM_BUILD_DIR" || exit $?

if [ "$PUSH" = y ]; then
  echo "Pushing chart $tgz..."
  if [ -z "$CHART_REPO" ]; then
    echo "$0: no chart repo specified" >&2
    exit 1
  fi

  cleanup=
  trap 'rm -f $cleanup' EXIT

  curl_opts=
  if [ "$PUSH" = y ] && [ -n "$CHART_REPO_CREDENTIALS_USR" ]; then
#    repo_host=$(echo "$CHART_REPO" | sed -r 's|^http(s?)://([^/]*)(.*)|\2|')
#    netrc=$(mktemp) || exit $?
#    cleanup="$cleanup $netrc"
#    chmod 0600 "$netrc" || exit $?
#    cat >"$netrc" <<EOF || exit $?
#machine $repo_host
#login $CHART_REPO_CREDENTIALS_USR
#password $CHART_REPO_CREDENTIALS_PSW
#EOF
#    curl_opts="--netrc-file \"$netrc\""
    curl_opts="-u $CHART_REPO_CREDENTIALS_USR:$CHART_REPO_CREDENTIALS_PSW"
  fi

  index_yaml=$(mktemp) || exit $?
  echo "Downloading chart repo index..."
  echo curl --silent --fail --show-error "$CHART_REPO/index.yaml" --output "$index_yaml"
  curl --silent --fail --show-error "$CHART_REPO/index.yaml" --output "$index_yaml" || exit $?
  cleanup="$cleanup $index_yaml"

  if [ "$OVERWRITE" = n ]; then
    if grep "$tgz" "$index_yaml" ; then
      echo "$0: $tgz already exists" >&2
      exit 1
    fi
  fi

  if [ -z "$CHART_REPO_UPLOAD_URL" ]; then
    case "$CHART_REPO" in
      */chartrepo/*)
        CHART_REPO_UPLOAD_URL="$(echo "$CHART_REPO" | sed 's|/chartrepo/|/api/chartrepo/|')/charts"
        ;;
      *)
        if grep -q 'charts/' "$index_yaml"; then
          CHART_REPO_UPLOAD_URL="$CHART_REPO/charts"
        else
          CHART_REPO_UPLOAD_URL="$CHART_REPO"
        fi
        ;;
    esac
  fi

  echo "Uploading $tgz..."
  echo curl --silent --fail --show-error -F "chart=@$HELM_BUILD_DIR/$tgz" "$CHART_REPO_UPLOAD_URL" || exit $?
  curl $curl_opts --silent --fail --show-error -F "chart=@$HELM_BUILD_DIR/$tgz" "$CHART_REPO_UPLOAD_URL" || exit $?
fi

echo "$tgz"
