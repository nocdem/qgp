#!/bin/bash
# Convert BIP39 wordlist to C header

echo "/**"
echo " * @file bip39_wordlist.h"
echo " * @brief BIP39 English wordlist (2048 words)"
echo " * @note Auto-generated from official BIP39 wordlist"
echo " * @note SHA256: 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
echo " */"
echo ""
echo "#ifndef QGP_BIP39_WORDLIST_H"
echo "#define QGP_BIP39_WORDLIST_H"
echo ""
echo "static const char *BIP39_WORDLIST[2048] = {"

awk '{printf "    \"%s\",\n", $0}' bip39_english.txt | sed '$ s/,$//'

echo "};"
echo ""
echo "#endif /* QGP_BIP39_WORDLIST_H */"
