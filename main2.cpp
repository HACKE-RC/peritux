#include <iostream>
#include <windows.h>
#include <iomanip>

std::string returnArch(const int machineArch);
void parseFileHeader(IMAGE_FILE_HEADER& ImgFileHeader);
void parseOptionalHeader(IMAGE_OPTIONAL_HEADER& ImgOptionalHeader);

int main(){
    HANDLE hFile = CreateFile("imp.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

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

    std::cout << "Signature: 0x" << std::hex << pNtHeaders->Signature << std::endl;
    parseFileHeader(ImgFileHeader);
    parseOptionalHeader(ImgOptionalHeader);



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
    std::cout << "Architecutre: " << returnArch(ImgFileHeader.Machine) << std::endl;
    std::cout << "Size of Section Table: " << ImgFileHeader.NumberOfSections << std::endl;
    std::cout << "Size of Optional Header: 0x" << ImgFileHeader.SizeOfOptionalHeader << std::endl;
    std::cout << "Relocs stripped: " << std::boolalpha << ((ImgFileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0) << std::endl;
    std::cout << "Executable: " << ((ImgFileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0) << std::endl;
    std::cout << "DLL: " << ((ImgFileHeader.Characteristics & IMAGE_FILE_DLL) != 0) << std::endl;
    std::cout << "Debug stripped: " << ((ImgFileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) != 0) << std::endl;
}

void parseOptionalHeader(IMAGE_OPTIONAL_HEADER& ImgOptionalHeader){
    std::cout << "Image type: " << returnImageType(ImgOptionalHeader.Magic) << std::endl;
    std::cout << "Size of Code section: " << returnImageType(ImgOptionalHeader.SizeOfCode) << std::endl;
    std::cout << "Image size: " << returnImageType(ImgOptionalHeader.SizeOfImage) << std::endl;
    std::cout << "Header size: " << ImgOptionalHeader.SizeOfHeaders << std::endl;
    std::cout << "Subsystem: " << returnImageSubsystem(ImgOptionalHeader.Subsystem) << std::endl;
    std::cout << "Subsystem: " << returnImageSubsystem(ImgOptionalHeader.Subsystem) << std::endl;
}
