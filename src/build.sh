#!/bin/sh
gcc -Wall -pedantic -o main main.c -ltls -lssl -lcrypto
