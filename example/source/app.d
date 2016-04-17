import elfhook;

extern(C)
{
  void original();
}

void myputs()
{
  import std.stdio : writeln;
  writeln("monkey patch.");
}

void main()
{
  import std.file : getcwd;
  auto so = getcwd() ~ "/liboriginal.so\0";
  const char* filename = so.ptr;
  const char* funcName = "puts\0".ptr;
  auto x = hook(filename, funcName, &myputs);
  original();
}
