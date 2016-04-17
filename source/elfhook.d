// taken from http://www.codeproject.com/Articles/70302/Redirecting-functions-in-shared-ELF-libraries.
module elfhook;

import core.sys.linux.elf;
import core.sys.posix.unistd;
import core.sys.posix.dlfcn;
import core.sys.posix.sys.mman;
import core.sys.posix.fcntl;

import core.stdc.string;
import core.stdc.stdlib;
import core.stdc.stdio;
import core.stdc.errno;

version(linux):
@system:
@nogc:

version(X86_64)
{
  alias Elf_Ehdr = Elf64_Ehdr;
  alias Elf_Shdr = Elf64_Shdr;
  alias Elf_Sym = Elf64_Sym;
  alias Elf_Rel = Elf64_Rela;
  alias ELF_R_SYM = ELF64_R_SYM;
  enum REL_DYN = ".rela.dyn";
  enum REL_PLT = ".rela.plt";
}
else version(X86)
{
  alias Elf_Ehdr = Elf32_Ehdr;
  alias Elf_Shdr = Elf32_Shdr;
  alias Elf_Sym = Elf32_Sym;
  alias Elf_Rel = Elf32_Rela;
  alias ELF_R_SYM = ELF32_R_SYM;
  enum REL_DYN = ".rel.dyn";
  enum REL_PLT = ".rel.plt";
}
else static assert(false, "Unsupported architecture.");


void* libraryAddressByHandle(const void* address)
{
  if (address is null) {
    return null;
  }
  return cast(void*) *cast(const size_t *) address;
}


int readHeader(int fd, ref Elf_Ehdr* header)
{
  header = cast(Elf_Ehdr*) malloc(Elf_Ehdr.sizeof);
  if (header is null) {
    return errno;
  }
  if (lseek(fd, 0, SEEK_SET) < 0) {
    free(header);
    return errno;
  }
  if (read(fd, header, Elf_Ehdr.sizeof) < 0) {
    free(header);
    return errno = EINVAL;
  }
  return 0;
}


int readSectionTable(int fd, const Elf_Ehdr* header, ref Elf_Shdr* table)
{
  if (header is null) {
    return EINVAL;
  }
  size_t size = header.e_shnum * Elf_Shdr.sizeof;
  table = cast(Elf_Shdr*) malloc(size);
  if (table is null) {
    return errno;
  }

  if (lseek(fd, header.e_shoff, SEEK_SET) < 0) {
    free(table);
    return errno;
  }

  if (read(fd, table, size) <= 0) {
    free(table);
    return errno = EINVAL;
  }

  return 0;
}


int readStringTable(int fd, const Elf_Shdr* section, ref char* strings)
{
  if (section is null) {
    return EINVAL;
  }
  strings = cast(char*) malloc(section.sh_size);
  if (strings is null) {
    return errno;
  }
  if (lseek(fd, section.sh_offset, SEEK_SET) < 0) {
    free(cast(void*) strings);
    return errno;
  }

  if (read(fd, cast(char*) strings, section.sh_size) <= 0) {
    free(cast(void*) strings);
    return errno = EINVAL;
  }

  return 0;
}

int readSymbolTable(int fd, const Elf_Shdr* section, ref Elf_Sym* table)
{
  if (section is null) {
    return EINVAL;
  }

  table = cast (Elf_Sym*) malloc(section.sh_size);
  if (table is null) {
    return errno;
  }

  if (lseek(fd, section.sh_offset, SEEK_SET) < 0) {
    free(table);
    return errno;
  }

  if (read(fd, table, section.sh_size) <= 0) {
    free(table);
    return errno = EINVAL;
  }
  return 0;
}


int sectionByIndex(int fd, const size_t index, ref Elf_Shdr* section)
{
  Elf_Ehdr* header;
  Elf_Shdr* sections;

  section = null;

  if (readHeader(fd, header) ||
      readSectionTable(fd, header, sections)) {
    return errno;
  }

  scope(exit) {
    free(header);
    free(sections);
  }

  if (index < header.e_shnum) {
    section = cast(Elf_Shdr*) malloc(Elf_Shdr.sizeof);
    if (section is null) {
      return errno;
    }
    memcpy(section, sections + index, Elf_Shdr.sizeof);
  }
  else {
    return EINVAL;
  }
  return 0;
}


int sectionByType(int fd, const size_t sectionType, ref Elf_Shdr* section)
{
  Elf_Ehdr* header;
  Elf_Shdr* sections;

  section = null;

  if (readHeader(fd, header) ||
      readSectionTable(fd, header, sections)) {
    return errno;
  }

  scope(exit) {
    free(header);
    free(sections);
  }

  foreach (i; 0 .. header.e_shnum) {
    if (sectionType == sections[i].sh_type) {
      section = cast(Elf_Shdr*) malloc(Elf_Shdr.sizeof);
      if (section is null) {
        return errno;
      }
      memcpy(section, sections + i, Elf_Shdr.sizeof);
      break;
    }
  }
  return 0;
}


int sectionByName(int fd, const char* sectionName, ref Elf_Shdr* section)
{
  Elf_Ehdr* header;
  Elf_Shdr* sections;
  char* strings;

  section = null;

  if (readHeader(fd, header) ||
      readSectionTable(fd, header, sections) ||
      readStringTable(fd, cast(const) &sections[header.e_shstrndx], strings)) {
    return errno;
  }

  scope(exit) {
    free(header);
    free(sections);
    free(cast(void*) strings);
  }

  foreach (i; 0 .. header.e_shnum) {
    if (!strcmp(sectionName, &strings[sections[i].sh_name])) {
      section = cast(Elf_Shdr*) malloc(Elf_Shdr.sizeof);
      if (section is null) {
        return errno;
      }
      memcpy(section, sections + i, Elf_Shdr.sizeof);
      break;
    }
  }
  return 0;
}


int symbolByName(int fd, Elf_Shdr* section, const char* name, ref Elf_Sym* symbol, ref size_t index)
{
  Elf_Shdr* stringsSection;
  char* strings;
  Elf_Sym* symbols;

  symbol = null;
  index = 0;

  if (sectionByIndex(fd, section.sh_link, stringsSection) ||
      readStringTable(fd, cast(const) stringsSection, strings) ||
      readSymbolTable(fd, section, symbols)) {
    return errno;
  }

  scope(exit) {
    free(stringsSection);
    free(cast(void*) strings);
    free(symbols);
  }

  size_t amount = section.sh_size / Elf_Sym.sizeof;

  foreach (i; 0 .. amount) {
    if (!strcmp(name, &strings[symbols[i].st_name])) {
      symbol = cast(Elf_Sym*) malloc(Elf_Sym.sizeof);
      if (symbol is null) {
        return errno;
      }
      memcpy(symbol, symbols + i, Elf_Sym.sizeof);
      index = i;
      break;
    }
  }
  return 0;
}

void* elfHook(const char* filename, const void* address, const char* name, const void* substitution)
{
  size_t pagesize = sysconf(_SC_PAGESIZE);

  Elf_Shdr* dynsym;  // ".dynsym"
  Elf_Shdr* rel_plt;  // ".rela.plt"
  Elf_Shdr* rel_dyn;  // ".rela.dyn"
  Elf_Sym* symbol;  //symbol table entry for symbol named "name"

  scope(exit) {
    if (dynsym !is null)  free(dynsym);
    if (rel_plt !is null) free(rel_plt);
    if (rel_dyn !is null) free(rel_dyn);
    if (symbol !is null)  free(symbol);
  }

  Elf_Rel* rel_plt_table;  //array with ".rel.plt" entries
  Elf_Rel* rel_dyn_table;  //array with ".rel.dyn" entries

  size_t name_index = void;
  size_t rel_plt_amount = void;  // amount of ".rel.plt" entries
  size_t rel_dyn_amount = void;  // amount of ".rel.dyn" entries
  size_t *name_address = null;

  void *original;  //address of the symbol being substituted

  if (address is null || name is null || substitution is null) {
    return original;
  }

  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    return original;
  }
  scope(exit) close(fd);

  if (
    sectionByType(fd, SHT_DYNSYM, dynsym) || dynsym is null ||
    symbolByName(fd, dynsym, name, symbol, name_index) || symbol is null ||
    sectionByName(fd, REL_PLT, rel_plt) || rel_plt is null ||
    sectionByName(fd, REL_DYN, rel_dyn) || rel_dyn is null) {
    return original;
  }

  rel_plt_table = cast(Elf_Rel*) ((cast(size_t) address) + rel_plt.sh_addr);
  rel_plt_amount = rel_plt.sh_size / Elf_Rel.sizeof;

  rel_dyn_table = cast(Elf_Rel*) ((cast(size_t) address) + rel_dyn.sh_addr);
  rel_dyn_amount = rel_dyn.sh_size / Elf_Rel.sizeof;

  foreach (i; 0 .. rel_plt_amount) {
    if (ELF_R_SYM(rel_plt_table[i].r_info) == name_index) {
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

  if (original) {
    return original;
  }

  foreach (i;  0 .. rel_dyn_amount) {
    if (ELF_R_SYM(rel_dyn_table[i].r_info) == name_index) {
      // get the relocation address (address of a relative CALL (0xE8) instruction's argument)
      name_address = cast(size_t*) ((cast(size_t) address) + rel_dyn_table[i].r_offset);

      if (!original) {
        // calculate an address of the original function by a relative CALL (0xE8) instruction's argument.
        original = cast(void*) (*name_address + cast(size_t) name_address + size_t.sizeof);
      }

      // mark a memory page that contains the relocation as writable.
      mprotect(cast(void*) ((cast(size_t) name_address) & (((size_t.sizeof)-1) ^ (pagesize - 1))), pagesize, PROT_READ | PROT_WRITE);

      if (errno) {
        return null;
      }

      // calculate a new relative CALL (0xE8) instruction's argument for the substitutional function and write it down.
      *name_address = cast(size_t) substitution - cast(size_t) name_address - size_t.sizeof;

      // mark a memory page that contains the relocation back as executable.
      mprotect(cast(void*) ((cast(size_t) name_address) & (((size_t.sizeof)-1) ^ (pagesize - 1))), pagesize, PROT_READ | PROT_EXEC);

      if (errno) {
        // then restore the original function address.
        *name_address = cast(size_t) original - cast(size_t) name_address - size_t.sizeof;
        return null;
      }
    }
  }
  return original;
}


void* hook(const char* filename, const char* functionName, const void* substitutionAddress)
{
  if (filename is null) {
    return null;
  }

  void* handle = dlopen(filename, RTLD_LAZY);
  if (handle is null) {
    return null;
  }
  void* address = libraryAddressByHandle(handle);
  if (address is null) {
    return null;
  }
  return elfHook(filename, address, functionName, substitutionAddress);
}
