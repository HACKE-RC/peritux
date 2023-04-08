#include <iostream>
#include <windows.h>
#include <iomanip>
#include <vector>

std::string returnArch(const int machineArch);
DWORD resolveRVAtoFileOffset(DWORD RVA, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader);
void parseFileHeader(IMAGE_FILE_HEADER& ImgFileHeader);
void parseOptionalHeader(IMAGE_OPTIONAL_HEADER& ImgOptionalHeader);
void parseSectionHeaders(PIMAGE_SECTION_HEADER pImgSectionHeader, WORD& ImgNoOfSections);
void parseImports(PIMAGE_DATA_DIRECTORY pImageDataDirectory, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader, unsigned char* pBuffer);
void parseExports(PIMAGE_DATA_DIRECTORY pImageDataDirectory, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader, unsigned char* pBuffer);

bool isDLL = false;

int main(int argc, char* argv[]){
   if (argc != 2){
      std::cout << "Please provide the filename!" << std::endl;
      return -1;
   }

    HANDLE hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE){
        std::cout << "[ERR] The provided file does not exist!" << std::endl;
        return -1;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE){
        std::cout << "[ERR] Unable to get the file size!" << std::endl;
        CloseHandle(hFile);
        return -1;
    }

    // Read file into a buffer.
    auto pBuffer = new BYTE[dwFileSize];
    bool rResult = ReadFile(hFile, pBuffer, dwFileSize, NULL, NULL);
    if (!rResult){
        std::cout << "[ERR] Unable to read the file!" << std::endl;
        CloseHandle(hFile);
        delete[] pBuffer;
        return -1;
    }

//    Verify the MS header of 0x4d5a
    if (*(WORD*)pBuffer != IMAGE_DOS_SIGNATURE){
        std::cout << "[ERR] Provided file has invalid signature!" << std::endl;
        CloseHandle(hFile);
        delete[] pBuffer;
        return -1;
    }

//    Get pointers to the PE Headers
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pBuffer;
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pBuffer + pDosHeader->e_lfanew);

    IMAGE_FILE_HEADER ImgFileHeader = (IMAGE_FILE_HEADER)(pNtHeaders->FileHeader);
    IMAGE_OPTIONAL_HEADER ImgOptionalHeader = (IMAGE_OPTIONAL_HEADER)(pNtHeaders->OptionalHeader);
    PIMAGE_DATA_DIRECTORY pImgDataDirectory = (PIMAGE_DATA_DIRECTORY)ImgOptionalHeader.DataDirectory;
    pImgDataDirectory++;

    WORD ImgTotalSections = ImgFileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pImgSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    parseSectionHeaders(pImgSectionHeader, ImgTotalSections);

    std::cout << "Signature: 0x" << std::hex << pNtHeaders->Signature << std::dec << std::endl;
    parseFileHeader(ImgFileHeader);
    parseOptionalHeader(ImgOptionalHeader);
    parseImports(pImgDataDirectory, ImgTotalSections, pImgSectionHeader, pBuffer);
    // Parsing exports only if the PE is a DLL.
    if (isDLL){
        parseExports(pImgDataDirectory, ImgTotalSections, pImgSectionHeader, pBuffer);
    }

    delete[] pBuffer;
}

std::string returnArch(const int machineArch) {
    switch (machineArch) {
        case IMAGE_FILE_MACHINE_AMD64:
            return "AMD64";
        case IMAGE_FILE_MACHINE_I386:
            return "I386 Family";
        case IMAGE_FILE_MACHINE_IA64:
            return "Intel Itanium Family";
        default:
            return "Unknown";
    }
}

std::string returnImageType(const int magicNumber){
    switch (magicNumber){
        case 0x10b:
            return "PE32";
        case 0x20b:
            return "PE32+";
        default:
            return "Unrecognized executable format!";
    }
}

std::string returnImageSubsystem(const int subsysNumber){
    switch (subsysNumber){
        case IMAGE_SUBSYSTEM_NATIVE:
            return "Native subsystem for device drivers and native Windows processes.";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            return "Windows GUI subsystem.";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            return "Windows CUI subsystem. (Console)";
        default:
            return "Unrecognized!";
    }
}

void parseFileHeader(IMAGE_FILE_HEADER& ImgFileHeader){
    std::cout << "Architecture: " << returnArch(ImgFileHeader.Machine) << std::endl;
    std::cout << "Size of Section Table: " << ImgFileHeader.NumberOfSections << std::endl;
    std::cout << "Size of Optional Header: 0x" << ImgFileHeader.SizeOfOptionalHeader << std::endl;
    std::cout << "Relocs stripped: " << std::boolalpha << ((ImgFileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0) << std::endl;
    std::cout << "Executable: " << ((ImgFileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0) << std::endl;
    std::cout << "DLL: " << ((ImgFileHeader.Characteristics & IMAGE_FILE_DLL) != 0) << std::endl;
    isDLL = ((ImgFileHeader.Characteristics & IMAGE_FILE_DLL) != 0);
    std::cout << "Debug stripped: " << ((ImgFileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) != 0) << std::endl;
}

void parseOptionalHeader(IMAGE_OPTIONAL_HEADER& ImgOptionalHeader){
    std::cout << "Image type: " << returnImageType(ImgOptionalHeader.Magic) << std::endl;
    std::cout << "Size of Code section: " << returnImageType(ImgOptionalHeader.SizeOfCode) << std::endl;
    std::cout << "Image size: " << returnImageType(ImgOptionalHeader.SizeOfImage) << std::endl;
    std::cout << "Header size: " << ImgOptionalHeader.SizeOfHeaders << std::endl;
    std::cout << "Subsystem: " << returnImageSubsystem(ImgOptionalHeader.Subsystem) << std::endl;
}

void parseSectionHeaders(PIMAGE_SECTION_HEADER pImgSectionHeader, WORD& ImgNoOfSections){
    for (int i = 0; i < ImgNoOfSections; i++) {
        std::cout << i+1 << ". " << pImgSectionHeader->Name << std::endl;
        std::cout << "\tVirtual Size: " << pImgSectionHeader->Misc.VirtualSize << std::endl;
        std::cout << "\tRaw Data Size: " << pImgSectionHeader->SizeOfRawData << std::endl;
        std::cout << "\tCharacteristics: " << std::endl;
        std::cout << "\t\tMEM_READ: " << std::boolalpha << ((pImgSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) != 0)<< std::endl;
        std::cout << "\t\tMEM_EXECUTE: " << std::boolalpha << ((pImgSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)<< std::endl;
        std::cout << "\t\tMEM_SHARED: " << std::boolalpha << ((pImgSectionHeader->Characteristics & IMAGE_SCN_MEM_SHARED) != 0)<< std::endl;
        std::cout << "\t\tCNT_CODE: " << std::boolalpha << ((pImgSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) != 0)<< std::endl;
        pImgSectionHeader++;
    }

}

DWORD resolveRVAtoFileOffset(DWORD RVA, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader){
    int index;

    for (int i = 0; i < ImgTotalSections; i++){
        if (RVA >= pImgSectionHeader->VirtualAddress && RVA < (pImgSectionHeader->VirtualAddress +pImgSectionHeader->Misc.VirtualSize)){
            index = i;
            break;
        }
        pImgSectionHeader++;
    }

    return (RVA - pImgSectionHeader->VirtualAddress) + pImgSectionHeader->PointerToRawData;
}

void parseImports(PIMAGE_DATA_DIRECTORY pImageDataDirectory, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader, unsigned char* pBuffer){

//    f -> file offset
    DWORD fDataDirectory = resolveRVAtoFileOffset(pImageDataDirectory->VirtualAddress, ImgTotalSections, pImgSectionHeader);
    PIMAGE_IMPORT_DESCRIPTOR pImgImportDescriptor;
    PIMAGE_IMPORT_DESCRIPTOR pTemp;
    int totalDirectory = 0;

    pImgImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pBuffer + fDataDirectory);
    pTemp = (PIMAGE_IMPORT_DESCRIPTOR)(pBuffer + fDataDirectory);

    while (true){
        if (pImgImportDescriptor->Name == 0x00000000 && pImgImportDescriptor->FirstThunk == 0x00000000){
            totalDirectory -= 1 ;
            break;
        }
        pImgImportDescriptor++;
        totalDirectory++;
    }
    std::cout << "Total Imports: " << totalDirectory+1 << std::endl;

    pImgImportDescriptor = pTemp;

    for (int i = 0; i <= totalDirectory; i++){
        char* dllName = (char*)(pBuffer + resolveRVAtoFileOffset(pImgImportDescriptor->Name, ImgTotalSections, pImgSectionHeader));

        // getting the Import Lookup Table address from Import Table
        // original first thunk = ILT
        PIMAGE_THUNK_DATA pILT = (PIMAGE_THUNK_DATA)(pBuffer + resolveRVAtoFileOffset(pImgImportDescriptor->OriginalFirstThunk, ImgTotalSections, pImgSectionHeader));

        std::cout << "\t" << i+1 << ". " << dllName << std::endl;
        while (pILT->u1.AddressOfData != 0x00000000){
            if (pILT->u1.Ordinal & IMAGE_ORDINAL_FLAG){
                WORD ordinal = (WORD)(pILT->u1.Ordinal & ~IMAGE_ORDINAL_FLAG);
                std::cout << "\t[O]: " << ordinal << std::endl;
            }
            else{
                auto pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pBuffer+ resolveRVAtoFileOffset(pILT->u1.AddressOfData, ImgTotalSections, pImgSectionHeader));
                std::cout << "\t[N]: " << pImgImportByName->Name << std::endl;
            }
            pILT++;
        }

        pImgImportDescriptor++;
    }

}
