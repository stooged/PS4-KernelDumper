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
FILESIZE=$(stat -c%s "bin/KernelDumper.bin")
PNAME=$"Kernel Dumper"
cp exploit.template html_payload/KernelDumper.html
sed -i -f - html_payload/KernelDumper.html << EOF
s/#NAME#/$PNAME/g
s/#BUF#/$FILESIZE/g
s/#PAY#/$(cat html_payload/payload.js)/g
EOF
rm -f KernelDumper/KernelDumper.bin
rm -f html_payload/payload.js
