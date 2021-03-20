#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#define BUFFER_LEN 10

const char *OPEN_ERROR = "Unable to open file";
const char *READ_HEADER_FAILED = "Invalid executable header";
const char *READ_SECTION_FAILED = "Failed to read the section of the executable";
const char *WRITE_FILE_OPEN_FAILED = "Failed to open files for writing";

const int CODE_SECTION_FLAG = 0x20;

void throw_exception(const char *message) {
    printf("%s", message);
    exit(1);
}

void print_section_data(FILE *write_file, int n, const IMAGE_SECTION_HEADER *current_section) {
    fprintf(write_file, "Number of section: %d\n", n);
    fprintf(write_file, "Section name: %s\n", current_section->Name);
    fprintf(write_file, "Virtual address: 0x%lX\n", current_section->VirtualAddress);
    fprintf(write_file, "raw data size: 0x%lX\n", current_section->SizeOfRawData);
    fprintf(write_file, "raw data pointer(offset): 0x%lX\n", current_section->PointerToRawData);
    fprintf(write_file, "relocation pointer(offset): 0x%lX\n", current_section->PointerToRelocations);
    fprintf(write_file, "pointer to line numbers: 0x%lX\n", current_section->PointerToLinenumbers);
    fprintf(write_file, "number of relocations: 0x%hX\n", current_section->NumberOfRelocations);
    fprintf(write_file, "number of line numbers: 0x%hX\n", current_section->NumberOfLinenumbers);
    fprintf(write_file, "characteristics: 0x%lX\n", current_section->Characteristics);
}

void write_binary_code(FILE *write_file, FILE *incoming_file, const IMAGE_SECTION_HEADER *current_section) {
    long int last_incoming_file_pointer = ftell(incoming_file);
    BYTE buffer[BUFFER_LEN];
    fseek(incoming_file, current_section->PointerToRawData, SEEK_SET);
    DWORD virtual_size = current_section->Misc.VirtualSize;

    DWORD i = 0;
    while (i < virtual_size) {
        DWORD count = virtual_size - i >= BUFFER_LEN ? BUFFER_LEN : virtual_size - i;
        fread(buffer, sizeof (BYTE), count, incoming_file);
        fwrite(buffer, sizeof (BYTE), count, write_file);
        i += count;
    }
    fseek(incoming_file, last_incoming_file_pointer, SEEK_SET);
}

int main() {
    FILE *exec_file = fopen("Minecraft.exe", "rb");
    if (exec_file == NULL) {
        throw_exception(OPEN_ERROR);
    }

    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS nt_headers;

    if (fread(&dos_header, sizeof (IMAGE_DOS_HEADER), 1, exec_file) < 1) {
        throw_exception(READ_HEADER_FAILED);
    }
    if (fseek(exec_file, dos_header.e_lfanew, SEEK_SET)
            || fread(&nt_headers, sizeof (nt_headers), 1, exec_file) < 1) {
        throw_exception(READ_HEADER_FAILED);
    }

    DWORD entry_point = nt_headers.OptionalHeader.AddressOfEntryPoint;

    FILE *meta_data_file = fopen("sections.txt", "w");
    FILE *program_binary_code = fopen("binary_code.bin", "wb");

    if (meta_data_file == NULL || program_binary_code == NULL) {
        throw_exception(WRITE_FILE_OPEN_FAILED);
    }

    WORD sections_count = nt_headers.FileHeader.NumberOfSections;

    IMAGE_SECTION_HEADER current_section;

    for (WORD i = 0; i < sections_count; i++) {
        if (fread(&current_section, sizeof (IMAGE_SECTION_HEADER), 1, exec_file) < 1) {
            throw_exception(READ_SECTION_FAILED);
        }
        print_section_data(meta_data_file, i + 1, &current_section);
        fprintf(meta_data_file, "\n");

        if (current_section.Characteristics & CODE_SECTION_FLAG) {
            write_binary_code(program_binary_code, exec_file, &current_section);
        }
    }
    fprintf(meta_data_file, "\nАдрес начала выполнения: 0x%lX\n", entry_point);

    fclose(exec_file);
    fclose(meta_data_file);
    fclose(program_binary_code);
    return 0;
}
