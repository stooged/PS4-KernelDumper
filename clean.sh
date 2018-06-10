#!/bin/bash
pushd tool
make clean
popd
pushd KernelDumper
make clean
popd
rm -f html_payload/KernelDumper.html
rm -f bin/KernelDumper.bin

