#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <string.h> // added for string operations

//for each menu function
struct fun_desc {
    char *name;
    char key;
    void (*fun)();
};

// variables to support up to 2 files mapped at the same time
int current_fd[2] = {-1, -1}; // array of file descriptors
void *map_start[2] = {NULL, NULL}; // array of pointers to the mapping start of files
off_t file_size[2] = {0, 0}; // array of file sizes
int num_of_files = 0; // counter for open files
int debug_mode = 0; 

void examine_elf_file() {
    // check if we already reached the limit of 2 files
    if (num_of_files >= 2) {
        printf("Error: Maximum of 2 files already mapped.\n");
        return;
    }

    char filename[100];
    printf("enter ELF file name: ");
    // limit the input width so it cannot overflow the buffer
    scanf("%99s", filename);

    // opening the file (read only) into the correct array index
    current_fd[num_of_files] = open(filename, O_RDONLY);
    if (current_fd[num_of_files] < 0) {
        perror("Failed to open file");
        return;
    }

    // finding the file size (by moving the "curser" to end of file)
    file_size[num_of_files] = lseek(current_fd[num_of_files], 0, SEEK_END);
    if (file_size[num_of_files] < 0) {
        perror("lseek failed");
        close(current_fd[num_of_files]);
        current_fd[num_of_files] = -1;
        return;
    }

    // mapping file to memory:
    // null: the OS will determine the adress
    //prot_read: read only permission
    //map_private: changes in memory won't influence original file
    //current_fd: the file which we want to map
    //0: map from first byte in file
    map_start[num_of_files] = mmap(NULL, file_size[num_of_files], PROT_READ, MAP_PRIVATE, current_fd[num_of_files], 0);
    if (map_start[num_of_files] == MAP_FAILED) {
        perror("mmap failed");
        close(current_fd[num_of_files]);
        current_fd[num_of_files] = -1;
        return;
    }

    if (debug_mode) {
        printf("Debug: mapped file '%s', FD: %d, Size: %ld bytes\n", 
               filename, current_fd[num_of_files], file_size[num_of_files]);
    }

    // convert the pointer to ELF header structure
    Elf32_Ehdr *header = (Elf32_Ehdr *) map_start[num_of_files];

    // check the magic number (including byte 0) before using the header.
    // if it is not a real ELF file, undo the mapping and refuse to continue.
    unsigned char *ident = header->e_ident;
    if (file_size[num_of_files] < (off_t)sizeof(Elf32_Ehdr) ||
        ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') {
        printf("Error: '%s' is not an ELF file\n", filename);
        munmap(map_start[num_of_files], file_size[num_of_files]);
        close(current_fd[num_of_files]);
        current_fd[num_of_files] = -1;
        map_start[num_of_files] = NULL;
        return;
    }

    // printing details:
    printf("magic bytes: %c %c %c\n", header->e_ident[1], header->e_ident[2], header->e_ident[3]);
    // print the data encoding scheme taken from byte EI_DATA of e_ident
    printf("data encoding: %s\n",
           ident[EI_DATA] == ELFDATA2LSB ? "2's complement, little endian" :
           ident[EI_DATA] == ELFDATA2MSB ? "2's complement, big endian" : "none/unknown");
    printf("entry point: 0x%x\n", header->e_entry);
    printf("section header offset: %d\n", header->e_shoff); //where the section header table starts
    printf("amount of section headers: %d\n", header->e_shnum);
    printf("size of section header entry: %d\n", header->e_shentsize); //size of each section header
    printf("program header offset: %d\n", header->e_phoff);
    printf("number of program headers: %d\n", header->e_phnum);
    printf("size of program header entry: %d\n", header->e_phentsize); 

    // increase the counter so the next file goes to the next index
    num_of_files++;
}

// temporary functions
void toggle_debug_mode() {
    if (debug_mode == 0) {
        debug_mode = 1;
        printf("Debug flag now on\n");
    } else {
        debug_mode = 0;
        printf("Debug flag now off\n");
    }
}

void print_section_names() {
    // check if at least one file is mapped
    if (num_of_files == 0) {
        printf("Error: No file currently mapped.\n");
        return;
    }

    // loop over all open files
    for (int k = 0; k < num_of_files; k++) {
        Elf32_Ehdr *header = (Elf32_Ehdr *)map_start[k];
        Elf32_Shdr *shdr = (Elf32_Shdr *)(map_start[k] + header->e_shoff);

        //find section header of strings table
        Elf32_Shdr *string_table_entry = &shdr[header->e_shstrndx];
        
        //calculate the actual string table in memory
        char *string_table = (char *)(map_start[k] + string_table_entry->sh_offset);

        if (debug_mode) {
            printf("Debug: shstrndx = %d, string table offset = 0x%x\n", 
                   header->e_shstrndx, string_table_entry->sh_offset);
        }

        // print which file we are currently showing
        printf("\nFile %d sections:\n", k + 1);
        printf("[Nr] Name                 Addr     Off    Size   Type\n");

        for (int i = 0; i < header->e_shnum; i++) {
            //get the name (using offset)
            char *name = string_table + shdr[i].sh_name;
            
            //print with fixed size collumn width
            printf("[%2d] %-20s %08x %06x %06x %x\n", 
                   i, name, shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_size, shdr[i].sh_type);
        }
    }
}

void print_symbols() {
    // check if at least one file is mapped
    if (num_of_files == 0) {
        printf("Error: No file currently mapped.\n");
        return;
    }

    // loop over all open files
    for (int k = 0; k < num_of_files; k++) {
        Elf32_Ehdr *header = (Elf32_Ehdr *)map_start[k];
        Elf32_Shdr *shdr = (Elf32_Shdr *)(map_start[k] + header->e_shoff);

        //find the dict of strings of section names (to print section name of each symbol)
        Elf32_Shdr *shstrtab_entry = &shdr[header->e_shstrndx];
        char *shstrtab = (char *)(map_start[k] + shstrtab_entry->sh_offset);

        for (int i = 0; i < header->e_shnum; i++) {
            //check if cur sectoi is symbol table
            if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
                
                //set the pointer to the actual symbol table
                Elf32_Sym *symtab = (Elf32_Sym *)(map_start[k] + shdr[i].sh_offset);
                
                //calculate amount of symbols in table
                int num_symbols = shdr[i].sh_size / shdr[i].sh_entsize;

                if (debug_mode) {
                    printf("Debug: Symbol table size = %d bytes, number of symbols = %d\n", 
                           shdr[i].sh_size, num_symbols);
                }

                //find the specific string dict of the strings table with sh_link
                char *sym_strtab = (char *)(map_start[k] + shdr[shdr[i].sh_link].sh_offset);

                //print title for table with file number
                printf("\nFile %d: Symbol table '%s' contains %d entries:\n", 
                       k + 1, shstrtab + shdr[i].sh_name, num_symbols);
                // SecIdx column added so the format matches the required one (value, section index, name)
                printf("[Nr] Value    SecIdx Size SectionName      Name\n");

                //print each symbol
                for (int j = 0; j < num_symbols; j++) {
                    char *sym_name = sym_strtab + symtab[j].st_name;
                    
                    //special check to find where the symbol is defined
                    char *sec_name;
                    if (symtab[j].st_shndx == SHN_UNDEF) {
                        sec_name = "UND"; // undifined symbol
                    } else if (symtab[j].st_shndx == SHN_ABS) {
                        sec_name = "ABS"; // absolute value symbol
                    } else if (symtab[j].st_shndx < header->e_shnum) {
                        //get sectio  name from section names dict
                        sec_name = shstrtab + shdr[symtab[j].st_shndx].sh_name;
                    } else {
                        sec_name = "UNKNOWN";
                    }

                    // print the section index (st_shndx) together with the rest of the fields
                    printf("[%2d] %08x %6d %4d %-14s %s\n",
                           j, symtab[j].st_value, symtab[j].st_shndx, symtab[j].st_size, sec_name, sym_name);
                }
            }
        }
    }
}

void print_relocations() {
    // check if at least one file is mapped
    if (num_of_files == 0) {
        printf("Error: No file currently mapped.\n");
        return;
    }

    // loop over all open files
    for (int k = 0; k < num_of_files; k++) {
        Elf32_Ehdr *header = (Elf32_Ehdr *)map_start[k];
        
        // pointer to the start of the section header table, acts like an array for the sections
        Elf32_Shdr *shdr = (Elf32_Shdr *)(map_start[k] + header->e_shoff);

        // string table for the section names (to print the table header)
        char *shstrtab = (char *)(map_start[k] + shdr[header->e_shstrndx].sh_offset);

        // flag that stays 0 until we find at least one relocation section in this file
        int found_rel = 0;

        for (int i = 0; i < header->e_shnum; i++) {
            // look for relocation sections (usually SHT_REL in 32-bit)
            if (shdr[i].sh_type == SHT_REL) {

                // we found a relocation section, remember it for the "No relocations" check
                found_rel = 1;
                
                // pointer to the relocation table itself and calc the number of entries
                Elf32_Rel *rel = (Elf32_Rel *)(map_start[k] + shdr[i].sh_offset);
                int num_rels = shdr[i].sh_size / shdr[i].sh_entsize;

                if (debug_mode) {
                    printf("Debug: Relocation table size = %d bytes, number of entries = %d\n", 
                           shdr[i].sh_size, num_rels);
                }

                // find the symbol table linked to this relocation section using sh_link
                Elf32_Shdr *symtab_shdr = &shdr[shdr[i].sh_link];
                Elf32_Sym *symtab = (Elf32_Sym *)(map_start[k] + symtab_shdr->sh_offset);

                // find the string table of the symbol table using sh_link of the symbol table
                char *strtab = (char *)(map_start[k] + shdr[symtab_shdr->sh_link].sh_offset);

                // print file number in the title
                printf("\nFile %d: Relocation section '%s' at offset 0x%x contains %d entries:\n",
                       k + 1, shstrtab + shdr[i].sh_name, shdr[i].sh_offset, num_rels);
                printf(" Offset     Info     Type      Sym.Value  Sym. Name\n");

                // loop through all relocation entries
                for (int j = 0; j < num_rels; j++) {
                    // extract the index and type using the elf macros
                    int sym_idx = ELF32_R_SYM(rel[j].r_info);
                    int rel_type = ELF32_R_TYPE(rel[j].r_info);

                    // get the matching symbol from the symbol table
                    Elf32_Sym *sym = &symtab[sym_idx];
                    
                    // get the actual symbol name
                    char *sym_name = strtab + sym->st_name;

                    printf("%08x  %08x %-9d %08x   %s\n",
                           rel[j].r_offset, rel[j].r_info, rel_type, sym->st_value, sym_name);
                }
            }
        }

        // if this file had no relocation sections at all, say so (as the task requires)
        if (!found_rel) {
            printf("\nFile %d: No relocations\n", k + 1);
        }
    }
}

// helper function to locate symtab, strtab, and calculate number of symbols for a given file index
void get_symbol_table_info(int file_idx, Elf32_Sym **symtab, char **strtab, int *num_syms) {
    Elf32_Ehdr *hdr = (Elf32_Ehdr *)map_start[file_idx];
    Elf32_Shdr *shdr = (Elf32_Shdr *)(map_start[file_idx] + hdr->e_shoff);

    // loop through all sections to find the symbol table
    for (int i = 0; i < hdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            // set the pointers to the correct addresses in memory
            *symtab = (Elf32_Sym *)(map_start[file_idx] + shdr[i].sh_offset);
            *num_syms = shdr[i].sh_size / shdr[i].sh_entsize;
            *strtab = (char *)(map_start[file_idx] + shdr[shdr[i].sh_link].sh_offset);
            return;
        }
    }
}

// helper that counts how many symbol tables a given file has (used to enforce "exactly one")
int count_symbol_tables(int file_idx) {
    Elf32_Ehdr *hdr = (Elf32_Ehdr *)map_start[file_idx];
    Elf32_Shdr *shdr = (Elf32_Shdr *)(map_start[file_idx] + hdr->e_shoff);
    int count = 0;
    for (int i = 0; i < hdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) count++;
    }
    return count;
}

// helper function to check symbols of one file against another
void check_symbols_against_other(Elf32_Sym *symtab_A, int num_syms_A, char *strtab_A,
                                 Elf32_Sym *symtab_B, int num_syms_B, char *strtab_B,
                                 int check_duplicates) {
                                     
    // loop through file A symbols (skip dummy symbol index 0)
    for (int i = 1; i < num_syms_A; i++) {
        char *sym_name_A = strtab_A + symtab_A[i].st_name;
        
        // skip internal symbols with no names
        if (strlen(sym_name_A) == 0) continue;

        int found_in_B = 0;
        int defined_in_B = 0;
        
        // search for the exact same symbol name in file B
        for (int j = 1; j < num_syms_B; j++) {
            char *sym_name_B = strtab_B + symtab_B[j].st_name;
            if (strcmp(sym_name_A, sym_name_B) == 0) {
                found_in_B = 1;
                // if the section index is not undefined, it means it is defined
                if (symtab_B[j].st_shndx != SHN_UNDEF) defined_in_B = 1; 
                break;
            }
        }

        int defined_in_A = (symtab_A[i].st_shndx != SHN_UNDEF);

        // rule 1: undefined in A and not defined in B
        if (!defined_in_A && (!found_in_B || !defined_in_B)) {
            printf("Symbol %s undefined\n", sym_name_A);
        } 
        // rule 2: multiply defined (only if the flag allows checking duplicates)
        else if (check_duplicates && defined_in_A && found_in_B && defined_in_B) {
            printf("Symbol %s multiply defined\n", sym_name_A);
        }
    }
}

void check_files_for_merge() {
    // verify we have exactly 2 files open
    if (num_of_files < 2) {
        printf("Error: Need exactly 2 mapped files for merge check.\n");
        return;
    }

    // each file must contain exactly one symbol table, otherwise we do not support it
    if (count_symbol_tables(0) != 1 || count_symbol_tables(1) != 1) {
        printf("feature not supported\n");
        return;
    }

    Elf32_Sym *symtab1 = NULL, *symtab2 = NULL;
    char *strtab1 = NULL, *strtab2 = NULL;
    int num_syms1 = 0, num_syms2 = 0;

    // fetch symbol table info for both files using the helper (passing addresses with &)
    get_symbol_table_info(0, &symtab1, &strtab1, &num_syms1);
    get_symbol_table_info(1, &symtab2, &strtab2, &num_syms2);

    // if one of them is missing a symbol table, we can't compare
    if (!symtab1 || !symtab2) {
        printf("feature not supported (missing symtab)\n");
        return;
    }

    // pass 1: check file 1 against file 2 (check_duplicates = 1)
    check_symbols_against_other(symtab1, num_syms1, strtab1, symtab2, num_syms2, strtab2, 1);

    // pass 2: check file 2 against file 1 (check_duplicates = 0)
    check_symbols_against_other(symtab2, num_syms2, strtab2, symtab1, num_syms1, strtab1, 0);
}


void merge_elf_files() {
    if (num_of_files < 2) {
        printf("Error: Need exactly 2 mapped files to merge.\n");
        return;
    }

    // create the new output file
    int fd_out = open("out.ro", O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd_out < 0) {
        perror("Failed to create out.ro");
        return;
    }

    Elf32_Ehdr *hdr1 = (Elf32_Ehdr *)map_start[0];
    Elf32_Ehdr *hdr2 = (Elf32_Ehdr *)map_start[1];

    // step 1: prepare a copy of the elf header for the new file
    Elf32_Ehdr new_hdr = *hdr1;

    // write the initial header to the file to save space (we will update e_shoff later)
    write(fd_out, &new_hdr, sizeof(Elf32_Ehdr));

    // step 2: copy the section header table from file 1 to memory as our draft
    int sht_size = hdr1->e_shnum * hdr1->e_shentsize;
    Elf32_Shdr *new_sht = malloc(sht_size);
    memcpy(new_sht, map_start[0] + hdr1->e_shoff, sht_size);

    // pointers to string tables to compare section names
    Elf32_Shdr *shdr1 = (Elf32_Shdr *)(map_start[0] + hdr1->e_shoff);
    char *shstrtab1 = (char *)(map_start[0] + shdr1[hdr1->e_shstrndx].sh_offset);

    Elf32_Shdr *shdr2 = (Elf32_Shdr *)(map_start[1] + hdr2->e_shoff);
    char *shstrtab2 = (char *)(map_start[1] + shdr2[hdr2->e_shstrndx].sh_offset);

    // keep track of where we are writing in the new file (starts after the elf header)
    int current_offset = sizeof(Elf32_Ehdr);

    // step 3: loop through all sections in our draft (skip section 0 which is null)
    for (int i = 1; i < hdr1->e_shnum; i++) {
        char *sec_name = shstrtab1 + new_sht[i].sh_name;

        // if the section has no data in file (like .bss), just update offset but don't write
        if (new_sht[i].sh_type == SHT_NOBITS || new_sht[i].sh_size == 0) {
            new_sht[i].sh_offset = current_offset;
            continue;
        }

        // save the new offset in our draft
        new_sht[i].sh_offset = current_offset;

        // check if section is mergable
        if (strcmp(sec_name, ".text") == 0 || strcmp(sec_name, ".data") == 0 || strcmp(sec_name, ".rodata") == 0) {
            
            // write file 1 part
            write(fd_out, map_start[0] + shdr1[i].sh_offset, shdr1[i].sh_size);
            current_offset += shdr1[i].sh_size;

            // find corresponding section in file 2 and append it
            for (int j = 1; j < hdr2->e_shnum; j++) {
                char *name2 = shstrtab2 + shdr2[j].sh_name;
                if (strcmp(sec_name, name2) == 0) {
                    // write file 2 part
                    write(fd_out, map_start[1] + shdr2[j].sh_offset, shdr2[j].sh_size);
                    
                    // update the new size in our draft (size1 + size2)
                    new_sht[i].sh_size += shdr2[j].sh_size;
                    current_offset += shdr2[j].sh_size;
                    break;
                }
            }
        } else {
            // not a mergable section (like .symtab or .strtab), just copy from file 1
            write(fd_out, map_start[0] + shdr1[i].sh_offset, shdr1[i].sh_size);
            current_offset += shdr1[i].sh_size;
        }
    }

    // step 4: write the updated section header table (our draft) to the end of the file
    new_hdr.e_shoff = current_offset; // tell the elf header where the table is now!
    write(fd_out, new_sht, sht_size);

    // step 5: rewind to the start of the file and rewrite the updated elf header
    lseek(fd_out, 0, SEEK_SET);
    write(fd_out, &new_hdr, sizeof(Elf32_Ehdr));

    // cleanup
    close(fd_out);
    free(new_sht);
    printf("Merged file created successfully as 'out.ro'\n");
}

void quit() { 
    // unmap memory and close all open files before exiting
    for (int i = 0; i < num_of_files; i++) {
        if (map_start[i] != NULL && map_start[i] != MAP_FAILED) {
            munmap(map_start[i], file_size[i]);
        }
        if (current_fd[i] != -1) {
            close(current_fd[i]);
        }
    }
    exit(0); 
}

// the menu array
struct fun_desc menu[] = {
    {"Toggle >D<ebug Mode", 'D', toggle_debug_mode},
    {"Examine ELF >F<ile", 'F', examine_elf_file},
    {"Print Section >N<ames", 'N', print_section_names},
    {"Print >S<ymbols", 'S', print_symbols},
    {"Print >R<elocations", 'R', print_relocations},
    {">C<heck Files for Merge", 'C', check_files_for_merge},
    {">M<erge ELF Files", 'M', merge_elf_files},
    {">Q<uit", 'Q', quit},
    {NULL, 0, NULL} // סמן לסוף המערך
};

int main() {
    char choice;
    
    while (1) {
        printf("\nChoose action:\n");
        // print menu
        for (int i = 0; menu[i].name != NULL; i++) {
            printf("%s\n", menu[i].name);
        }
        
        // get user input
        printf("choice: ");
        scanf(" %c", &choice); 
        
        // look for the char in the array and call the function
        int found = 0;
        for (int i = 0; menu[i].name != NULL; i++) {
            if (menu[i].key == choice) {
                menu[i].fun();
                found = 1;
                break;
            }
        }
        
        if (!found) {
            printf("Invalid operation\n");
        }
    }
    return 0;
}