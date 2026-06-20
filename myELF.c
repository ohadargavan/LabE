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

void examine_elf_file() {
    // check if we already reached the limit of 2 files
    if (num_of_files >= 2) {
        printf("Error: Maximum of 2 files already mapped.\n");
        return;
    }

    char filename[100];
    printf("enter ELF file name: ");
    scanf("%s", filename);

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

    // convert the pointer to ELF header structure
    Elf32_Ehdr *header = (Elf32_Ehdr *) map_start[num_of_files];
    
    // printing details:
    printf("magic bytes: %c %c %c\n", header->e_ident[1], header->e_ident[2], header->e_ident[3]);
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
void toggle_debug_mode() { printf("Not implemented yet\n"); }

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

                //find the specific string dict of the strings table with sh_link
                char *sym_strtab = (char *)(map_start[k] + shdr[shdr[i].sh_link].sh_offset);

                //print title for table with file number
                printf("\nFile %d: Symbol table '%s' contains %d entries:\n", 
                       k + 1, shstrtab + shdr[i].sh_name, num_symbols);
                printf("[Nr] Value    Size SectionName      Name\n");

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

                    printf("[%2d] %08x %4d %-14s %s\n",
                           j, symtab[j].st_value, symtab[j].st_size, sec_name, sym_name);
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

        for (int i = 0; i < header->e_shnum; i++) {
            // look for relocation sections (usually SHT_REL in 32-bit)
            if (shdr[i].sh_type == SHT_REL) {
                
                // pointer to the relocation table itself and calc the number of entries
                Elf32_Rel *rel = (Elf32_Rel *)(map_start[k] + shdr[i].sh_offset);
                int num_rels = shdr[i].sh_size / shdr[i].sh_entsize;

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


void merge_elf_files() { printf("Not implemented yet\n"); }

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