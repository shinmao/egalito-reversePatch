#ifndef EGALITO_PASS_REVERSEPATCH_H
#define EGALITO_PASS_REVERSEPATCH_H

#include "chunkpass.h"

class ReversePatch : public ChunkPass {
private:
  std::vector<Function*> rmFunc;
  std::vector<Function*> appendFunc;
  std::vector<std::string> target_func;
  std::vector<Block*> rmBlk;
  std::vector<Block*> insbeforeB;
  std::vector<Block*> insbeforeBlk;
  std::vector<std::string> target_block;
  std::vector<Instruction*> rmIns;
  std::vector<Instruction*> insbeforeI;
  std::vector<Instruction*> insbeforeIns;
public:
  ReversePatch(){}
  virtual void visit(Function *function);
  virtual void visit(Block *block);
};

#endif
