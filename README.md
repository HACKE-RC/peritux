# PEritux
PEritux (peri-tux) comes from the latin work "peritus" from "expert.
This is a small PE parser which parses all the important Portable Executable Header information such the File Header, Section Header, Optional Header, Import Directory and Export Directory. PEritux does not use any OOP at all, so if you're a beginner, the code can be easy to read for you.

## Compilation
### g++
```bash 
g++ -o PEritux main.cpp PEritux_funcs.cpp
```

## Usage
```bash
- PEritux [filename]
```

## Documentation of each function used in the project.

### Function: returnArch

#### Input

-   int machineArch: the machine architecture

#### Output

-   std::string: returns a string describing the architecture

#### Description

The `returnArch` function takes an integer representing a machine architecture value as an input, then uses a switch-case statement to return a string representation of that architecture.

### Function: returnImageType

#### Input

-   int magicNumber: a value used to determine the type of the executable

#### Output

-   std::string: returns a string describing the executable format

#### Description

The `returnImageType` function takes an integer representing a magic number value as an input, then uses a switch-case statement to determine the type of the executable format and returns a string representation.

### Function: returnImageSubsystem

#### Input

-   int subsysNumber: a value used to determine the subsystem of the executable

#### Output

-   std::string: returns a string describing the subsystem of the executable

#### Description

The `returnImageSubsystem` function takes an integer representing a subsystem number as an input, then uses a switch-case statement to determine the subsystem of the executable and returns a string representation.

### Function: parseFileHeader

#### Input

-   IMAGE_FILE_HEADER& ImgFileHeader: a reference to an IMAGE_FILE_HEADER structure

#### Output

-   None

#### Description

The `parseFileHeader` function takes a reference to an IMAGE_FILE_HEADER structure as an input and prints information about the file header to the console.

### Function: parseOptionalHeader

#### Input

-   IMAGE_OPTIONAL_HEADER& ImgOptionalHeader: a reference to an IMAGE_OPTIONAL_HEADER structure

#### Output

-   None

#### Description

The `parseOptionalHeader` function takes a reference to an IMAGE_OPTIONAL_HEADER structure as an input and prints information about the optional header to the console.

### Function: parseSectionHeaders

#### Input

-   PIMAGE_SECTION_HEADER pImgSectionHeader: a pointer to an array of IMAGE_SECTION_HEADER structures
-   WORD& ImgNoOfSections: a reference to the number of sections in the file

#### Output

-   None

#### Description

The `parseSectionHeaders` function takes a pointer to an array of IMAGE_SECTION_HEADER structures and a reference to the number of sections in the file as inputs and prints information about each section to the console.

### Function: parseImports

#### Input

-   PIMAGE_DATA_DIRECTORY pImageDataDirectory: a pointer to an IMAGE_DATA_DIRECTORY structure
-   WORD& ImgTotalSections: a reference to the number of sections in the file
-   PIMAGE_SECTION_HEADER pImgSectionHeader: a pointer to an array of IMAGE_SECTION_HEADER structures
-   unsigned char* pBuffer: a pointer to the file buffer

#### Output

-   None

#### Description

The `parseImports` function takes a pointer to an IMAGE_DATA_DIRECTORY structure, a reference to the number of sections in the file, a pointer to an array of IMAGE_SECTION_HEADER structures, and a pointer to the file buffer as inputs. The function parses the import directory and prints information about each import to the console.

### Function: parseExports

#### Input

-   IMAGE_DATA_DIRECTORY ImageExportDirectory: an IMAGE_DATA_DIRECTORY structure
-   WORD& ImgTotalSections: a reference to the number of sections in the file
-   PIMAGE_SECTION_HEADER pImgSectionHeader: a pointer to an array of IMAGE_SECTION_HEADER structures
-   unsigned char* pBuffer: a pointer to the file buffer

#### Output

-   None

#### Description

The `parseExports` function takes an IMAGE_DATA_DIRECTORY structure, a reference to the number of sections in the file, a pointer to an array of IMAGE_SECTION_HEADER structures, and a pointer to the file buffer as inputs.
