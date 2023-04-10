#include <windows.h>
#include "PEritux.h"
#include <iostream>

int main(int argc, char* argv[]) {
    // Check if a file name is provided
    if (argc != 2) {
        std::cout << "Please provide the filename!" << std::endl;
        return -1;
    }

    // Open the file
    HANDLE hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cout << "[ERR] The provided file does not exist!" << std::endl;
        return -1;
    }

    // Get the file size
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        std::cout << "[ERR] Unable to get the file size!" << std::endl;
        CloseHandle(hFile);
        return -1;
    }

    // Read the file into a buffer
    auto pBuffer = new BYTE[dwFileSize];
    bool rResult = ReadFile(hFile, pBuffer, dwFileSize, NULL, NULL);
    if (!rResult) {
        std::cout << "[ERR] Unable to read the file!" << std::endl;
        CloseHandle(hFile);
        delete[] pBuffer;
        return -1;
    }

    // Verify the MS header of 0x4d5a
    if (*(WORD*)pBuffer != IMAGE_DOS_SIGNATURE) {
        std::cout << "[ERR] Provided file has invalid signature!" << std::endl;
        CloseHandle(hFile);
        delete[] pBuffer;
        return -1;
    }

    // Get pointers to the PE Headers
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pBuffer;
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pBuffer + pDosHeader->e_lfanew);
    IMAGE_FILE_HEADER ImgFileHeader = (IMAGE_FILE_HEADER)(pNtHeaders->FileHeader);
    IMAGE_OPTIONAL_HEADER ImgOptionalHeader = (IMAGE_OPTIONAL_HEADER)(pNtHeaders->OptionalHeader);
    PIMAGE_DATA_DIRECTORY pImgDataDirectory = (PIMAGE_DATA_DIRECTORY)ImgOptionalHeader.DataDirectory;
    IMAGE_DATA_DIRECTORY ImgExportDirectory = (IMAGE_DATA_DIRECTORY)ImgOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    pImgDataDirectory++;

    WORD ImgTotalSections = ImgFileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pImgSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    // Parse the section headers
    parseSectionHeaders(pImgSectionHeader, ImgTotalSections);

    // Print the signature and parse the headers
    std::cout << "Signature: 0x" << std::hex << pNtHeaders->Signature << std::dec << std::endl;
    bool isDLL = parseFileHeader(ImgFileHeader);
    parseOptionalHeader(ImgOptionalHeader);
    parseImports(pImgDataDirectory, ImgTotalSections, pImgSectionHeader, pBuffer);
    // Parsing exports only if the PE is a DLL.
    if (isDLL){
        parseExports(ImgExportDirectory, ImgTotalSections, pImgSectionHeader, pBuffer);
    }

    delete[] pBuffer;
}
