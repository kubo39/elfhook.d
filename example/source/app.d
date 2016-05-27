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
    auto address = hook("liboriginal.so", "puts", &myputs);
    assert(address !is null);
    original();
}
