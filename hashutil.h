// hashutil.h

#ifndef HASHUTIL_H
#define HASHUTIL_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_HASH_SIZE 32

int sha256FileHex(const char* filepath, char* outHex);

void printHash(const BYTE hash[SHA256_HASH_SIZE]);

#ifdef __cplusplus
}
#endif

#endif 
