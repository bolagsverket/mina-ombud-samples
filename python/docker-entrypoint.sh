#!/bin/sh

case "$1" in
  sh | /*) exec "$@" ;;
  bash) shift; exec sh "$@" ;;
  server)
    shift
    exec python -m minaombud.server "$@"
    ;;
  *)
    exec python -m minaombud.cli "$@"
    ;;
esac
