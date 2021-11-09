#ifndef EGALITO_PASS_REVERSEPATCH_H
#define EGALITO_PASS_REVERSEPATCH_H

#include <vector>
#include <unordered_map>
#include "chunkpass.h"
#include "instr/visitor.h"
#include "instr/concrete.h"

class FuncSignature {
public:
  int numBB;
  int numInst;
  std::string funcname;
  std::vector<std::string> mnemonic;
  std::vector<std::string> instType;
  std::unordered_map<std::string, int> fq_mnemonic;
  std::unordered_map<std::string, int> fq_type;
  std::vector<std::string> caller;
  std::vector<std::string> callee;
  FuncSignature() {}
};

class ReversePatch : public ChunkPass {
private:
  Module *comparedModule;
  FuncSignature fs;
  std::unordered_map<std::string, FuncSignature> elfsign;
  std::unordered_map<std::string, FuncSignature> cmpelfsign;
  std::unordered_map<std::string, FuncSignature> fsign;
public:
  ReversePatch(Module *comparedModule) : comparedModule(comparedModule) {}
  virtual ~ReversePatch() { std::cout << "Revdone\n"; }
  void compare();
  void visit(Module *module);
  void visit(FunctionList *functionlist);
  void visit(Function *function);
  void visit(Block *block);
  void visit(Instruction *instruction);
};
#endif
