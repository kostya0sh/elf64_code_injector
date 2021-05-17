 // modify .note.ABI-tag section header
    Elf64_Shdr* sh_strtab = &s_header[e_header->e_shstrndx];
    const char* const sh_strtab_p = target + sh_strtab->sh_offset;
    printf("\n");
    Elf64_Shdr* target_header;
    for (int i = 0; i < e_header->e_shnum; i++) {
        const char* sh_name = sh_strtab_p + s_header[i].sh_name;
        printf("section header #%d name: %d/%s\n", i, s_header[i].sh_name, sh_name);
        if (strcmp(sh_name, ".note.ABI-tag") == 0) {
            printf("\t^^^ this is a header which we were searching for!\n");
            target_header = &s_header[i];
            
            s_header[i].sh_type = SHT_PROGBITS;
            s_header[i].sh_addr = pt_note_header->p_vaddr;
            s_header[i].sh_offset = pt_note_header->p_offset;
            s_header[i].sh_size = pt_note_header->p_memsz + self_size;
            s_header[i].sh_addralign = 16;
            s_header[i].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        }
    }
