#include "PEritux.h"

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

bool parseFileHeader(IMAGE_FILE_HEADER& ImgFileHeader){
    std::cout << "--- FILE HEADERS ---" << std::endl;
    std::cout << "Architecture: " << returnArch(ImgFileHeader.Machine) << std::endl;
    std::cout << "Size of Section Table: " << ImgFileHeader.NumberOfSections << std::endl;
    std::cout << "Size of Optional Header: 0x" << ImgFileHeader.SizeOfOptionalHeader << std::endl;
    std::cout << "Relocs stripped: " << std::boolalpha << ((ImgFileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0) << std::endl;
    std::cout << "Executable: " << ((ImgFileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0) << std::endl;
    std::cout << "DLL: " << ((ImgFileHeader.Characteristics & IMAGE_FILE_DLL) != 0) << std::endl;
    std::cout << "Debug stripped: " << ((ImgFileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) != 0) << std::endl;
    std::cout << std::endl;
    return ((ImgFileHeader.Characteristics & IMAGE_FILE_DLL) != 0);
}

void parseOptionalHeader(IMAGE_OPTIONAL_HEADER& ImgOptionalHeader){
    std::cout << "--- OPTIONAL HEADERS ---" << std::endl;
    std::cout << "Image type: " << returnImageType(ImgOptionalHeader.Magic) << std::endl;
    std::cout << "Size of Code section: " << returnImageType(ImgOptionalHeader.SizeOfCode) << std::endl;
    std::cout << "Image size: " << returnImageType(ImgOptionalHeader.SizeOfImage) << std::endl;
    std::cout << "Header size: " << ImgOptionalHeader.SizeOfHeaders << std::endl;
    std::cout << "Subsystem: " << returnImageSubsystem(ImgOptionalHeader.Subsystem) << std::endl;
    std::cout << std::endl;
}

void parseSectionHeaders(PIMAGE_SECTION_HEADER pImgSectionHeader, WORD& ImgNoOfSections){
    std::cout << "--- SECTION HEADERS ---" << std::endl;
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
    std::cout << std::endl;
}

DWORD resolveRVAtoFileOffset(DWORD RVA, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader){
    int index;
    // Loop through all the sections in the executable image.
    for (int i = 0; i < ImgTotalSections; i++){

        // Check if the RVA falls within the current section.
        if (RVA >= pImgSectionHeader->VirtualAddress && RVA < (pImgSectionHeader->VirtualAddress +pImgSectionHeader->Misc.VirtualSize)){

            // If the RVA falls within the current section, store the index of the current section.
            index = i;
            break;
        }

        // Move to the next section header in the executable image.
        pImgSectionHeader++;
    }

    // Calculate the file offset of the RVA by subtracting the virtual address of the section containing the RVA from the RVA,
    // and then adding the raw data pointer of that section.
    return (RVA - pImgSectionHeader->VirtualAddress) + pImgSectionHeader->PointerToRawData;

}
// This function is used to parse and print the names of imported DLLs and their imported functions from the PE file
// Inputs:
// - pImageDataDirectory: pointer to IMAGE_DATA_DIRECTORY structure that contains the virtual address and size of the import directory
// - ImgTotalSections: total number of sections in the PE file
// - pImgSectionHeader: pointer to IMAGE_SECTION_HEADER structure that contains information about each section
// - pBuffer: pointer to the buffer containing the PE file data
void parseImports(PIMAGE_DATA_DIRECTORY pImageDataDirectory, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader, unsigned char* pBuffer){

    std::cout << "--- IMPORTS---" << std::endl;
    // Resolve the virtual address of the import directory to its file offset
    DWORD fDataDirectory = resolveRVAtoFileOffset(pImageDataDirectory->VirtualAddress, ImgTotalSections, pImgSectionHeader);
    PIMAGE_IMPORT_DESCRIPTOR pImgImportDescriptor;
    PIMAGE_IMPORT_DESCRIPTOR pTemp;
    int totalDirectory = 0;

    // Point pImgImportDescriptor to the first IMAGE_IMPORT_DESCRIPTOR structure
    pImgImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pBuffer + fDataDirectory);
    // Save the value of pImgImportDescriptor to pTemp to be used later
    pTemp = (PIMAGE_IMPORT_DESCRIPTOR)(pBuffer + fDataDirectory);

    // Count the total number of IMAGE_IMPORT_DESCRIPTOR structures
    while (true){
        if (pImgImportDescriptor->Name == 0x00000000 && pImgImportDescriptor->FirstThunk == 0x00000000){
            totalDirectory -= 1 ;
            break;
        }
        pImgImportDescriptor++;
        totalDirectory++;
    }
    std::cout << "Total Imports: " << totalDirectory+1 << std::endl;

    // Reset pImgImportDescriptor to point to the first IMAGE_IMPORT_DESCRIPTOR structure
    pImgImportDescriptor = pTemp;

    // Loop through each IMAGE_IMPORT_DESCRIPTOR structure
    for (int i = 0; i <= totalDirectory; i++){
        // Get the name of the imported DLL
        char* dllName = (char*)(pBuffer + resolveRVAtoFileOffset(pImgImportDescriptor->Name, ImgTotalSections, pImgSectionHeader));

        // Get the Import Lookup Table address from Import Table
        // Original First Thunk = ILT
        PIMAGE_THUNK_DATA pILT = (PIMAGE_THUNK_DATA)(pBuffer + resolveRVAtoFileOffset(pImgImportDescriptor->OriginalFirstThunk, ImgTotalSections, pImgSectionHeader));

        // Print the name of the imported DLL
        std::cout << "\t" << i+1 << ". " << dllName << std::endl;

        // Loop through each imported function
        while (pILT->u1.AddressOfData != 0x00000000){
            if (pILT->u1.Ordinal & IMAGE_ORDINAL_FLAG){
                // If the imported function is imported by ordinal, print the ordinal number
                WORD ordinal = (WORD)(pILT->u1.Ordinal & ~IMAGE_ORDINAL_FLAG);
                std::cout << "\t[O]: " << ordinal << std::endl;
            }
            else{
                // If the imported function is imported by name, print the name
                auto pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pBuffer+ resolveRVAtoFileOffset(pILT->u1.AddressOfData, ImgTotalSections, pImgSectionHeader));
                std::cout << "\t[N]: " << pImgImportByName->Name << std::endl;
            }
            pILT++;
        }

        // Move to the next IMAGE_IMPORT_DESCRIPTOR structure
        pImgImportDescriptor++;
    }
    std::cout << std::endl;
}

void parseExports(IMAGE_DATA_DIRECTORY ImageExportDirectory, WORD& ImgTotalSections, PIMAGE_SECTION_HEADER pImgSectionHeader, unsigned char* pBuffer) {
    // calculating the file offset for the export directory using the RVA
    DWORD fDataDirectory = resolveRVAtoFileOffset((ImageExportDirectory.VirtualAddress), ImgTotalSections, pImgSectionHeader);
    PIMAGE_EXPORT_DIRECTORY pImgExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pBuffer + fDataDirectory);
    PIMAGE_EXPORT_DIRECTORY pTemp;
    pTemp = pImgExportDirectory;

    // getting the number of functions and names exported
    DWORD totalFunctions = pImgExportDirectory->NumberOfFunctions;
    DWORD totalNames = pTemp->NumberOfNames;

    std::cout << "--- EXPORTS ---" << std::endl;
    std::cout << "Total exported functions: " << totalFunctions << std::endl;
    std::cout << "Total exported names: " << totalNames << std::endl;

    // getting the address of the tables
    DWORD NameTable = pImgExportDirectory->AddressOfNames;
    DWORD OrdinalTable = pImgExportDirectory->AddressOfNameOrdinals;
    DWORD FunctionTable = pImgExportDirectory->AddressOfFunctions;

    PCSTR name;
    PULONG pNameTable = (PULONG)(pBuffer + resolveRVAtoFileOffset(NameTable, ImgTotalSections, pImgSectionHeader));
    PUSHORT pOrdinalTable = (PUSHORT)(pBuffer + resolveRVAtoFileOffset(OrdinalTable, ImgTotalSections, pImgSectionHeader));
    PULONG pFunctionTable = (PULONG)(pBuffer + resolveRVAtoFileOffset(FunctionTable, ImgTotalSections, pImgSectionHeader));

    // loop through all the exported functions
    for (DWORD i = 0; i < totalFunctions; i++) {
        name = nullptr;
        bool isOrdinal = true;

        // loop through all the exported names
        for (DWORD j = 0; j < totalNames; j++) {
            // if ordinaltable has an entry for a number, it would mean that it has a name
            if (pOrdinalTable[j] == i) {
                isOrdinal = false;
                name = (PCSTR)(pBuffer + resolveRVAtoFileOffset(pNameTable[j], ImgTotalSections, pImgSectionHeader));
                break;
            }
        }
        // if function is an ordinal function, then print it with [O]
        if (isOrdinal) {
            auto functionOrdinal = (WORD)(pImgExportDirectory->Base + i);
            std::cout << "\t[O]: " << functionOrdinal << std::endl;
        }
            // else print it with [N]
        else {
            std::cout << "\t[N]: " << name << std::endl;
        }
    }
}
