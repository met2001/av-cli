#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <math.h>
#include "hashutil.h"

#pragma comment(lib, "advapi32.lib");

typedef struct _PE_HEADERS
{
    IMAGE_DOS_HEADER* dosHeader;
    IMAGE_NT_HEADERS* ntHeaders;
    IMAGE_FILE_HEADER* fileHeader;
    IMAGE_OPTIONAL_HEADER* optionalHeader;
    IMAGE_SECTION_HEADER* sectionHeaders;
} PE_HEADERS;

typedef struct _PE_DETAILS
{
    char *filename;
    char *matches;
    int file_size;
    double fileEntroy;
    char *hash;

} PE_DETAILS;

typedef struct _PACKER_INDICATORS
{
    int has_unusual_section_names;
    int has_abnormal_section_count;

} PACKER_INDICATORS;

PE_HEADERS loadHeaders(char filepath[])
{
        HANDLE hFile = CreateFileA(
        filepath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open file.\n");
        exit(1);
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        printf("[-] Failed to create file mapping.\n");
        CloseHandle(hFile);
        exit(1);
    }

    LPVOID base = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        printf("[-] Failed to map view of file.\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        exit(1);
    }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Not a valid MZ file.\n");
        goto cleanup;
    }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Not a valid PE file.\n");
        goto cleanup;
    }

    IMAGE_OPTIONAL_HEADER* optionalHeader = &nt->OptionalHeader;
    if (!optionalHeader)
    {
        printf("[!] ERROR RECIEVING OPTIONAL HEADER\n");
        goto cleanup;
    }

    PE_HEADERS peHeaders;
    peHeaders.dosHeader = dos;
    peHeaders.ntHeaders = nt;
    peHeaders.fileHeader = &nt->FileHeader;
    peHeaders.optionalHeader = optionalHeader;
    peHeaders.sectionHeaders = (IMAGE_SECTION_HEADER*)
    ((BYTE*)peHeaders.optionalHeader + peHeaders.fileHeader->SizeOfOptionalHeader);
    
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return peHeaders;

    cleanup:
        UnmapViewOfFile(base);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        exit(1);
}

PACKER_INDICATORS check_for_packers(PE_HEADERS details)
{
    PACKER_INDICATORS indicators;
    int section_count = details.ntHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((uint8_t*)&details.ntHeaders->OptionalHeader + details.ntHeaders->FileHeader.SizeOfOptionalHeader);

    if (section_count < 2 || section_count > 20)
    {
        indicators.has_abnormal_section_count = 1;
    }
    for (int i = 0; i < section_count; i++)
    {
        char section_name[20] = {0};
        memcpy(section_name, sections[i].Name, 8);
        
        if (strstr(section_name, "UPX") ||
            strstr(section_name, "packed") ||
            strstr(section_name, "themida") ||
            strlen(section_name) == 0 ||
            !isprint(section_name[0]))
            {
                indicators.has_unusual_section_names = 1;
            }
        
    }
    
}

double fileEntropy(char *filepath)
{
    uint64_t map[256] = {0};
    unsigned char buf[1024 * 8];
    size_t bytesRead;
    size_t totalBytes = 0;

    FILE *f = fopen(filepath, "rb");
    if (!f)
    {
        printf("[!] Cannot open file: %s\n", filepath);
        exit(1);
    }

    while ((bytesRead = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        totalBytes += bytesRead;
        for (size_t i = 0; i < bytesRead; i++)
        {
            map[buf[i]]++;
        }
    }

    fclose(f);

    if (totalBytes == 0) return 0.0;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (map[i] == 0) continue;
        double freq = (double)map[i] / totalBytes;
        entropy += freq * log2(freq);
    }

    return -entropy;
}

PE_DETAILS getDetails(char *filepath)
{
    
    static char hex[SHA256_HASH_SIZE];  // static: persists after return
    DWORD filesize;
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributes(filepath))
    {
        LARGE_INTEGER size;
        size.HighPart = fileInfo.nFileSizeHigh;
        size.LowPart = fileInfo.nFileSizeLow;
        filesize = (DWORD)size.QuadPart;
    }
    PE_DETAILS details;
    details.fileEntroy = fileEntropy(filepath); // also set here
    details.filename = filepath;
    details.file_size = filesize;
    if (sha256FileHex(filepath, hex))
    {
        details.hash = hex;
    }
    else
    {
        details.hash = "ERROR";
    }

    return details;
}

void MoreOptions(PE_DETAILS details)
{
    Sleep(200);
    printf("> [0] Search SHA256 in database\n");
    Sleep(200);
    printf("> [1] Remove File\n");
    Sleep(200);
    printf("> [2] Exit\n");
    Sleep(200);
    int choice;
    printf("Option: ");
    scanf("%d", &choice);
    switch (choice)
    {
    case 0:
    
        char buffer[512];
        sprintf(buffer, "py C:\\Repos\\av-cli\\API\\hash_scan.py %s", details.hash);
        system(buffer);
        system("pause");
        break;
    
    case 1:
        if (remove(details.filename) == 0)
        {
            printf("> File deteled\n");
            system("pause");
        }
        else
        {
            printf("> Error deleting file\n");
            system("pause");
        }
        break;
    case 2:
        exit(1);
        break;
    default:
        printf("> Invalid choice\n");
        system("pause");
        break;
    }
}

void vSavetoDatabase(PE_DETAILS details)
{
    char buffer[512];
    sprintf(buffer, "py C:\\Repos\\av-cli\\database\\db_logic.py \"%s\" \"%s\" %.6f %d", details.filename, details.hash, details.fileEntroy, details.file_size);
    system(buffer);
}

void main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <path_to_exe>\n", argv[0]);
        system("pause");
        exit(1);
    }

    char cmd[512];
    char *filepath = argv[1];

    printf("> Summary\n");

    sprintf(cmd, "py C:\\Repos\\av-cli\\yara\\yara_scan.py \"%s\"", filepath); // EDIT PATH FOR YOUR USE CASE
    system(cmd);

    PE_HEADERS headers = loadHeaders(filepath);
    
    printf("> Sections: %d\n", headers.fileHeader->NumberOfSections);
    printf("> Checksum: %d\n", headers.optionalHeader->CheckSum);
    printf("> Entropy: %f\n", fileEntropy(filepath));

    // Nearly 30% of all malicious samples have an entropy of 7.2 or more versus 1% of legitimate samples.  https://practicalsecurityanalytics.com/file-entropy/
    if (fileEntropy(filepath) > 7.2)
    {
        printf("> Details: Likely malware or packed/obfuscated software\n");
    }
    else
    {
        printf("> Details: Unlikely to be malware based on entropy\n");
    }
    PE_DETAILS details = getDetails(filepath);

    printf("> SHA256: %s\n", details.hash);
    PACKER_INDICATORS indicators = check_for_packers(headers);
    if (indicators.has_abnormal_section_count && indicators.has_unusual_section_names)
    {
        printf("> Likely packed\n");
    }
    else if (indicators.has_abnormal_section_count)
    {
        printf("> Unusual number of sections\n");
    }
    else if (indicators.has_unusual_section_names)
    {
        printf("> Unusual section names (likely using a common packer)\n");
    }
    else
    {
        printf("> Further analysis needed\n");
    }

    vSavetoDatabase(details);
    MoreOptions(details);
}
