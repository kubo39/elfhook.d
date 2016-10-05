// taken from http://www.codeproject.com/Articles/70302/Redirecting-functions-in-shared-ELF-libraries.
module elfhook;

import core.sys.linux.elf;
import core.sys.posix.unistd;
import core.sys.posix.sys.mman;

import core.stdc.errno;

import std.exception;
import std.string : toStringz;
import std.conv : to;
import std.range : only, enumerate;

import sharedlib;
import elf;
import elf.low;


version(linux):
@system:

version(X86_64)
{
    alias Elf_Rel = Elf64_Rela;
    alias ELF_R_SYM = ELF64_R_SYM;
}
else version(X86)
{
    alias Elf_Rel = Elf32_Rela;
    alias ELF_R_SYM = ELF32_R_SYM;
}
else static assert(false, "Unsupported architecture.");


void* elfHook(ELF elf, const void* address, string name, void* substitution)
{
    assert(address !is null);
    assert(name !is null);
    assert(substitution !is null);

    size_t pagesize = sysconf(_SC_PAGESIZE);

    ELFSection dynsym;  // ".dynsym"
    ELFSection rel_plt;  // ".rela.plt"
    ELFSection rel_dyn;  // ".rela.dyn"
    ELFSymbol symbol;  //symbol table entry for symbol named "name"

    Elf_Rel *rel_plt_table;  //array with ".rel.plt" entries
    Elf_Rel *rel_dyn_table;  //array with ".rel.dyn" entries

    size_t name_index = void;
    size_t rel_plt_amount = void;  // amount of ".rel.plt" entries
    size_t rel_dyn_amount = void;  // amount of ".rel.dyn" entries
    size_t *name_address = null;

    void *original;  //address of the symbol being substituted

    foreach (section; elf.sections)
    {
        if (section.type == SectionType.dynamicLoaderSymbolTable)
            dynsym = section;
        if (section.name.to!string == ".rela.plt")
            rel_plt = section;
        if (section.name.to!string == ".rela.dyn")
            rel_dyn = section;
    }

    foreach (section; only(".symtab", ".dynsym"))
    {
        auto s = elf.getSection(section);
        foreach (i, sym; SymbolTable(s).symbols.enumerate)
        {
            if (name == sym.name)
            {
                symbol = sym;
                name_index = cast(size_t) i;
                goto L0;
            }
        }
    }

L0:

    rel_plt_table = cast(Elf_Rel*) ((cast(size_t) address) + rel_plt.address);
    rel_plt_amount = rel_plt.size / Elf_Rel.sizeof;

    rel_dyn_table = cast(Elf_Rel*) ((cast(size_t) address) + rel_dyn.address);
    rel_dyn_amount = rel_dyn.size / Elf_Rel.sizeof;

    foreach (i; 0 .. rel_plt_amount)
    {
        if (ELF_R_SYM(rel_plt_table[i].r_info) == name_index)
        {
            name_address = cast(size_t *) ((cast(size_t) address) + rel_plt_table[i].r_offset);

            // mark a memory page that contains the relocation as writable.
            mprotect(cast(void*) ((cast(size_t) name_address) & (((size_t.sizeof)-1) ^ (pagesize - 1))), pagesize, PROT_READ | PROT_WRITE);

            // save the original function address.
            original = cast(void*)* name_address;

            // and replace it with the substitution.
            *name_address = cast(size_t) substitution;

            break;  // the target symbol appears in ".rel.plt" only once.
        }
    }

    if (original)
        return original;

    foreach (i;  0 .. rel_dyn_amount)
    {
        if (ELF_R_SYM(rel_dyn_table[i].r_info) == name_index)
        {
            // get the relocation address (address of a relative CALL (0xE8) instruction's argument)
            name_address = cast(size_t*) ((cast(size_t) address) + rel_dyn_table[i].r_offset);

            if (!original)
                // calculate an address of the original function by a relative CALL (0xE8) instruction's argument.
                original = cast(void*) (*name_address + cast(size_t) name_address + size_t.sizeof);

            // mark a memory page that contains the relocation as writable.
            mprotect(cast(void*) ((cast(size_t) name_address) & (((size_t.sizeof)-1) ^ (pagesize - 1))), pagesize, PROT_READ | PROT_WRITE);

            if (errno)
                errnoEnforce(false, "failed to mprotect.");

            // calculate a new relative CALL (0xE8) instruction's argument for the substitutional function and write it down.
            *name_address = cast(size_t) substitution - cast(size_t) name_address - size_t.sizeof;

            // mark a memory page that contains the relocation back as executable.
            mprotect(cast(void*) ((cast(size_t) name_address) & (((size_t.sizeof)-1) ^ (pagesize - 1))), pagesize, PROT_READ | PROT_EXEC);

            if (errno)
            {
                // then restore the original function address.
                *name_address = cast(size_t) original - cast(size_t) name_address - size_t.sizeof;
                errnoEnforce(false, "failed to mprotect.");
            }
        }
    }
    return original;
}


void* hook(string filename, string functionName, void* substitutionAddress)
{
    assert(filename !is null, "No file given.");

    auto lib = new SharedLibrary(filename, RTLD_LAZY);
    const address = lib.getLoadedAddr;
    assert(address !is null, "failed to get address that libarary loaded.");
    return elfHook(ELF.fromFile(filename), address, functionName, substitutionAddress);
}
