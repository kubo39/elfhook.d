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

    const filename = getcwd() ~ "/liboriginal.so";
    const char* funcName = "puts\0".ptr;

    auto address = hook(filename, funcName, &myputs);
    assert(address !is null);  // Sucess for monkey-patching.
    original();
}
