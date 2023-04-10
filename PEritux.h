//
// Created by mister-rc on 10-04-2023.
//

#ifndef PERITUX_PERITUX_H
#define PERITUX_PERITUX_H

#include <iostream>
#include <windows.h>
#include <vector>

std::string returnArch(const int machineArch);
DWORD resolveRVAtoFileOffset(DWORD RVA, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader);
bool parseFileHeader(IMAGE_FILE_HEADER& ImgFileHeader);
void parseOptionalHeader(IMAGE_OPTIONAL_HEADER& ImgOptionalHeader);
void parseSectionHeaders(PIMAGE_SECTION_HEADER pImgSectionHeader, WORD& ImgNoOfSections);
void parseImports(PIMAGE_DATA_DIRECTORY pImageDataDirectory, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader, unsigned char* pBuffer);
void parseExports(IMAGE_DATA_DIRECTORY ImageExportDirectory, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader, unsigned char* pBuffer);

#endif //PERITUX_PERITUX_H
