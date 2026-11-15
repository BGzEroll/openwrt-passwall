#!/bin/sh
# procd supervises the exec'ed program; each argument remains an argument.
output=$1
shift
exec "$@" >>"$output" 2>&1
