#!/bin/sh

#
# Makefile for javadoc documentation.
# (C) 2015 Sebastian Deiss. All rights reserved.
#


APP_NAME="Java-XTS"
PACKAGES="sdeiss.crypto.block.mode.xts org.bouncycastle.crypto org.bouncycastle.crypto.engines org.bouncycastle.crypto.params"

echo "Creating javadoc for $APP_NAME\n"

if [ ! -d "docs/" ];
then
    mkdir "docs"
fi
cd docs/ && javadoc -author -version -private -sourcepath ../src/ -subpackages $PACKAGES
