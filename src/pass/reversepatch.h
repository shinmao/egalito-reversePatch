#ifndef EGALITO_PASS_REVERSEPATCH_H
#define EGALITO_PASS_REVERSEPATCH_H

#include <vector>
#include "chunkpass.h"
#include "instr/visitor.h"
#include "instr/concrete.h"

class ReversePatch : public ChunkPass {
private:
  Module *comparedModule;
  std::vector<std::string> elfsign;
  std::vector<std::string> cmpelfsign;
  std::vector<std::string> fsign;
  std::string sign;
public:
  ReversePatch(Module *comparedModule) : comparedModule(comparedModule) {}
  virtual ~ReversePatch() { std::cout << "Revdone\n"; }
  virtual void visit(Module *module);
  virtual void visit(FunctionList *functionlist);
  virtual void visit(Function *function);
  virtual void visit(Block *block);
  virtual void visit(Instruction *instruction);
};
#endif
