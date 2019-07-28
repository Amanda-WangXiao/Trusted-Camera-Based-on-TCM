#!/bin/bash

cd src
make clean
make 
cd -
cd instance/ca_center
ln -s $CUBESYSPATH/main/main_proc
mkdir tcmkey
mkdir pubkey
mkdir ekpub
cd -
cd instance/server
ln -s $CUBESYSPATH/main/main_proc
cd -
cd instance/user/ekget
ln -s $CUBESYSPATH/main/main_proc
cd -
cd instance/user/trust
ln -s $CUBESYSPATH/main/main_proc
mkdir tcmkey
mkdir pubkey
mkdir cert
cd -
cd instance/user/client
ln -s $CUBESYSPATH/main/main_proc
cd -
