#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>

//for each menu function
struct fun_desc {
    char *name;
    char key;
    void (*fun)();
};

int current_fd = -1; //file descriptor
void *map_start = NULL; //pointer to the mapping start of file in memory
off_t file_size = 0;

void examine_elf_file() {
    char filename[100];
    printf("enter ELF file name: ");
    scanf("%s", filename);

    // opening the file (read only)
    current_fd = open(filename, O_RDONLY);
    if (current_fd < 0) {
        perror("Failed to open file");
        return;
    }

    // finding the file size (by moving the "curser" to end of file)
    file_size = lseek(current_fd, 0, SEEK_END);
    if (file_size < 0) {
        perror("lseek failed");
        close(current_fd);
        current_fd = -1;
        return;
    }

    // mapping file to memory:
    // null: the OS will determine the adress
    //prot_read: read only permission
    //map_private: changes in memory won't influence original file
    //current_fd: the file which we want to map
    //0: map from first byte in file
    map_start = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, current_fd, 0);
    if (map_start == MAP_FAILED) {
        perror("mmap failed");
        close(current_fd);
        current_fd = -1;
        return;
    }

    // convert the pointer to ELF header structure
    Elf32_Ehdr *header = (Elf32_Ehdr *) map_start;
    
    // printing details:
    printf("magic bytes: %c %c %c\n", header->e_ident[1], header->e_ident[2], header->e_ident[3]);
    printf("entry point: 0x%x\n", header->e_entry);
    printf("section header offset: %d\n", header->e_shoff); //where the section header table starts
    printf("amount of section headers: %d\n", header->e_shnum);
    printf("size of section header entry: %d\n", header->e_shentsize); //size of each section header
    printf("program header offset: %d\n", header->e_phoff);
    printf("number of program headers: %d\n", header->e_phnum);
    printf("size of program header entry: %d\n", header->e_phentsize); 
}

// temporary functions
void toggle_debug_mode() { printf("Not implemented yet\n"); }
void print_section_names() {
    if (map_start == NULL) {
        printf("Error: No file currently mapped.\n");
        return;
    }

    Elf32_Ehdr *header = (Elf32_Ehdr *)map_start;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(map_start + header->e_shoff);

    //find section header of strings table
    Elf32_Shdr *string_table_entry = &shdr[header->e_shstrndx];
    
    //calculate the actual string table in memory
    char *string_table = (char *)(map_start + string_table_entry->sh_offset);

    printf("[Nr] Name                 Addr     Off    Size   Type\n");

    for (int i = 0; i < header->e_shnum; i++) {
        //get the name (using offset)
        char *name = string_table + shdr[i].sh_name;
        
        //print with fixed size collumn width
        printf("[%2d] %-20s %08x %06x %06x %x\n", 
               i, name, shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_size, shdr[i].sh_type);
    }
}

void print_symbols() {
    if (map_start == NULL) {
        printf("Error: No file currently mapped.\n");
        return;
    }

    Elf32_Ehdr *header = (Elf32_Ehdr *)map_start;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(map_start + header->e_shoff);

    //find the dict of strings of section names (to print section name of each symbol)
    Elf32_Shdr *shstrtab_entry = &shdr[header->e_shstrndx];
    char *shstrtab = (char *)(map_start + shstrtab_entry->sh_offset);

    for (int i = 0; i < header->e_shnum; i++) {
        //check if cur sectoi is symbol table
        if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
            
            //set the pointer to the actual symbol table
            Elf32_Sym *symtab = (Elf32_Sym *)(map_start + shdr[i].sh_offset);
            
            //calculate amount of symbols in table
            int num_symbols = shdr[i].sh_size / shdr[i].sh_entsize;

            //find the specific string dict of the strings table with sh_link
            char *sym_strtab = (char *)(map_start + shdr[shdr[i].sh_link].sh_offset);

            //print title for table
            printf("\nSymbol table '%s' contains %d entries:\n", 
                   shstrtab + shdr[i].sh_name, num_symbols);
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
void print_relocations() { printf("Not implemented yet\n"); }
void check_files_for_merge() { printf("Not implemented yet\n"); }
void merge_elf_files() { printf("Not implemented yet\n"); }
void quit() { 
    // later we implement freeing memory
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