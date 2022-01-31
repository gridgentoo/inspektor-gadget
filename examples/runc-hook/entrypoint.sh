#!/bin/sh

touch /tmp/hooks.log
tail -f /tmp/hooks.log &

if [ -x /hooks/prestart.sh ] ; then
  runc-hook -output "add,remove" -prestart /hooks/prestart.sh
else
  runc-hook -output "add,remove,config"
fi
