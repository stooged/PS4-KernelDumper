#!/bin/bash
set -e
pushd tool
make
popd
pushd KernelDumper
make
popd
mkdir -p bin
rm -f bin/KernelDumper.bin
cp KernelDumper/KernelDumper.bin bin/KernelDumper.bin
mkdir -p html_payload
tool/bin2js bin/KernelDumper.bin > html_payload/payload.js
sed "s/###/$(cat html_payload/payload.js)/" exploit.template > html_payload/KernelDumper.html
rm -f KernelDumper/KernelDumper.bin
rm -f html_payload/payload.js
