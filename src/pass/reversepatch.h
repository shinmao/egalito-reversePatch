#ifndef EGALITO_PASS_REVERSEPATCH_H
#define EGALITO_PASS_REVERSEPATCH_H

#include "chunkpass.h"

class ReversePatch : public ChunkPass {
public:
    ReversePatch() {}
    virtual void visit(Function *function);
    virtual void visit(Block *block);
};

#endif