#!/bin/bash

if [ $CUBESYSPATH == "" ]
then
    echo "can't find CUBESYSPATH"
    exit
fi

echo "CUBESYSPATH is ${CUBESYSPATH}"

cd src
make clean
make 
cd -
cd instance/key_test
ln -s $CUBESYSPATH/main/main_proc
mkdir tcmkey
mkdir pubkey
cd -
cd instance/ekget
ln -s $CUBESYSPATH/main/main_proc
cd -
cd instance/ca_center
ln -s $CUBESYSPATH/main/main_proc
mkdir ekpub
cd -
cd instance/pik_client
ln -s $CUBESYSPATH/main/main_proc
mkdir tcmkey
mkdir pubkey
mkdir cert
cd -
cd instance/pik_receiver
ln -s $CUBESYSPATH/main/main_proc
mkdir tcmkey
mkdir pubkey
mkdir cert
cd -
