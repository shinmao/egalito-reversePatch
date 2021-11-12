#ifndef EGALITO_PASS_REVERSEPATCH_H
#define EGALITO_PASS_REVERSEPATCH_H

#include <vector>
#include <set>
#include <unordered_map>
#include "chunkpass.h"
#include "instr/visitor.h"
#include "instr/concrete.h"

/**
 * Function Signature
 * numBB: number of basic block
 * numInst: number of instruction
 * numSyscall: number of syscall in each function, not including the one wrapped in libc
 * instType: sequence of instruction type, e.g. IsolatedInstruction, Controlflowinstruction
 * fq_: statistics of features
 * caller: who calls this function
 * callee: who is called by this function
 */

class FuncSignature {
public:
  int numBB = 0;
  int numInst = 0;
  int numSyscall = 0;
  std::string funcname;
  std::string signature;
  std::vector<std::string> mnemonic;
  std::vector<std::string> instType;
  std::vector<int> fq_mnemonic;
  std::vector<int> fq_type;
  std::vector<std::string> caller;
  std::vector<std::string> callee;
  std::vector<int> fq_calle;
  std::vector<std::string> callplt;
  std::vector<int> fq_callplt;
  FuncSignature() {}
};

class ReversePatch : public ChunkPass {
private:
  Module *comparedModule;
  FuncSignature fs;
  int inst_counter = 0;
  std::vector<std::string> initFunctionList;   // we can skip comparing on initFunction
  std::unordered_map<std::string, FuncSignature> elfsign;
  std::unordered_map<std::string, FuncSignature> cmpelfsign;
  std::unordered_map<std::string, FuncSignature> fsign;
  std::set<std::string> mnemonic_set;
  std::set<std::string> type_set;
  std::set<std::string> calle_set;
  std::set<std::string> plt_set;
public:
  ReversePatch(Module *comparedModule) : comparedModule(comparedModule) {}
  virtual ~ReversePatch() { std::cout << "Revdone\n"; }
  void compareLog();
  void mergeTable(std::unordered_map<std::string, FuncSignature> &elfsig);
  void hashsign(std::unordered_map<std::string, FuncSignature> &elfsig);
  void visit(Module *module);
  void visit(InitFunction *initFunction);
  void visit(FunctionList *functionlist);
  void visit(Function *function);
  void visit(Block *block);
  void visit(Instruction *instruction);
};
#endif
