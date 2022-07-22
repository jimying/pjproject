#!/bin/bash

APP=./pjturn-srv-x86_64-unknown-linux-gnu

#VG=valgrind
VG="valgrind --fair-sched=try"

rm -f n.log

# helgrind
$VG --tool=helgrind --log-file=n.log --suppressions=./sup_hel.txt --gen-suppressions=all  $APP

# memcheck
#$VG --tool=memcheck --leak-check=full --log-file=n.log --gen-suppressions=all  $APP

