#!/bin/bash
rm -f m.log
valgrind --tool=drd --log-file=m.log --suppressions=./sup.txt  ./pjturn-srv-x86_64-unknown-linux-gnu
