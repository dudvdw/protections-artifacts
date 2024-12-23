/*
   A YARA rule for detecting executable files
*/

import "pe"


rule Detect_PE_File
{
    meta:
        description = "Detect Windows PE executable files"
        author = "YourName"
        date = "2024-12-21"

    strings:
        // $mz_header = { 4D 5A } // 'MZ' header
        $pe_header = { 50 45 00 00 } // 'PE' header

    condition:
        uint16(0) == 0x5A4D and // Match 'MZ' at offset 0
        $pe_header in (0..1024) // Match 'PE' within the first 1KB
}


rule Detect_ELF_File
{
    meta:
        description = "Detect Linux ELF executable files"
        author = "YourName"
        date = "2024-12-21"

    strings:
        $elf_magic = { 7F 45 4C 46 } // ELF magic number

    condition:
        $elf_magic at 0 // Must appear at the start of the file
}


rule Detect_MachO_File
{
    meta:
        description = "Detect macOS Mach-O executable files"
        author = "YourName"
        date = "2024-12-21"

    strings:
        $mach_o_magic_32 = { FE ED FA CE } // Mach-O 32-bit magic number
        $mach_o_magic_64 = { FE ED FA CF } // Mach-O 64-bit magic number

    condition:
        $mach_o_magic_32 at 0 or $mach_o_magic_64 at 0
}


rule Detect_PE_with_Specific_Sections
{
    meta:
        description = "Detect PE files with suspicious .text or .rsrc sections"
        author = "YourName"
        date = "2024-12-21"

    condition:
        uint16(0) == 0x5A4D and
        for any section in pe.sections: (
            // section.name == ".text" and section.size > 100000 // Large code section
            section.name == ".text"
        )
}
