#!/bin/bash
rm -R mbedtls
wget -nc https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.27.0.zip -O mbedtls.zip
unzip -n mbedtls.zip
rm mbedtls.zip
mv mbedtls-2.27.0 mbedtls
