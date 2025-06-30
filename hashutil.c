#include "hashutil.h"
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

int sha256FileHex(const char* filepath, char* outHex) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE hash[SHA256_HASH_SIZE];
    BYTE buffer[4096];
    DWORD bytesRead;

    hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return 0;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return 0;
    }

    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return 0;
        }
    }

    DWORD hashLen = SHA256_HASH_SIZE;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return 0;
    }

    // Convert hash to hex string
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        sprintf(outHex + i * 2, "%02x", hash[i]);
    }
    outHex[SHA256_HASH_SIZE * 2] = '\0';

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return 1;
}

void printHash(const BYTE hash[SHA256_HASH_SIZE]) {
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}
