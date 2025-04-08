#!/bin/sh

case "$1" in
  sh | /*) exec "$@" ;;
  bash) shift; exec sh "$@" ;;
  server)
    shift
    exec python -m minaombud.server "$@"
    ;;
  minaombud-sample-*)
    exec "$@"
    ;;
  *)
    exec python -m minaombud.cli "$@"
    ;;
esac
