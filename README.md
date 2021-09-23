## Egalito ReversePatch
Develop patch on older version of OSS based on case of newer version.

## Egalito's original README follows
Egalito is a binary recompiler, designed for implementing security hardening.
It uses a low-level intermediate representation (EIR or Chunk) that accurately
reflects all aspects of a program binary. Egalito uses metadata present in
modern position-independent binaries to turn all cross-references into EIR
Links, allowing code to be arbitrarily rearranged without additional overhead.
Output generation in the form of ELFs or union ELFs is supported, and Egalito
provides a custom loader that allows it to bootstrap into a fully self-hosted
environment (parsing and transforming libegalito.so).

Egalito supports x86_64 and aarch64, with experimental support for RISC-V.

For more information, please visit: https://egalito.org

To build:
```
$ sudo apt-get install make g++ libreadline-dev gdb lsb-release unzip
$ sudo apt-get install libc6-dbg libstdc++6-7-dbg  # names may differ
$ git submodule update --init --recursive
$ make -j `nproc`
```

To test, try:
```
$ cd test/codegen && make && cd -
$ cd app && ./etelf -m ../src/ex/hello hello && ./hello && cd -
$ cd src && ./loader ex/hello && cd -
$ cd app && ./etshell
```

Other extensions:
- Python bindings and Python shell: see app/README-python
- Docker: see test/docker/README.md

## Egalito dev notes

### How to make my own tools with Egalito?
Add my own pass in `/src/pass`, and also update it in `etharden` or `etshell` as an option. Just need to `make` in `/app` directory, then it would be partially compiled and linked up.

### Some useful kits

#### `recurse()`
can be found in `dump.h`.  
```cpp
void recurse(Type *root) {
    for(auto child : root->getChildren()->genericIterable()) {
        child->accept(this);
    }
}
```
This function is used to iterate and visit the children.

#### `accept()`
```cpp
void Chunk::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
```
ChunkVisitor would dynamically cast to the chunk type,
```cpp
    virtual void visit(Program *program) {}
    virtual void visit(Module *module);
    virtual void visit(FunctionList *functionList);
    ...
    virtual void visit(Function *function);
    virtual void visit(Block *block);
    virtual void visit(Instruction *instruction);
    ...
```
This is how it works :)

#### `recalculate()`
can be found in `position.cpp`.  
In mutator's destructor, it would help us to do some awesome relocation work by calling `recalculate` over each chunk, over parent and children.  
```cpp
auto prev = chunk->getPreviousSibling();
if(prev) {
    auto parent = chunk->getParent();
    offset = (prev->getAddress() - parent->getAddress()) + prev->getSize();
}
else {
    offset = 0;
}
```
Each chunk will recalculate their relative offset to the parent chunk.