#!/bin/bash
#rm -f m.log
#valgrind --tool=drd --log-file=m.log --suppressions=./sup.txt  ./pjturn-srv-x86_64-unknown-linux-gnu
#valgrind --tool=drd --log-file=m.log --suppressions=./sup.txt --gen-suppressions=all  ./pjturn-srv-x86_64-unknown-linux-gnu


rm -f n.log
#valgrind --tool=helgrind --log-file=n.log --suppressions=./sup_hel.txt  ./pjturn-srv-x86_64-unknown-linux-gnu
valgrind --tool=helgrind --log-file=n.log --suppressions=./sup_hel.txt --gen-suppressions=all  ./pjturn-srv-x86_64-unknown-linux-gnu
