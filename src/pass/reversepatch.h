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
  std::string ref_funcname;
  FuncSignature fs;
  int inst_counter = 0;
  std::vector<std::string> initFunctionList;   // we can skip comparing on initFunction
  std::unordered_map<std::string, FuncSignature> elfsign;
  std::unordered_map<std::string, FuncSignature> cmpelfsign;
  // used for locate patched function: <hash sign, function name>
  std::unordered_map<std::string, std::string> elf;
  std::unordered_map<std::string, std::string> cmp;
  std::unordered_map<std::string, FuncSignature> fsign;
  std::set<std::string> mnemonic_set;
  std::set<std::string> type_set;
  std::set<std::string> calle_set;
  std::set<std::string> plt_set;
public:
  ReversePatch(Module *comparedModule, std::string funcname) : comparedModule(comparedModule), ref_funcname(funcname) {}
  virtual ~ReversePatch() { std::cout << "Revdone\n"; }
  void compareLog();
  void mergeTable(std::unordered_map<std::string, FuncSignature> &elfsig);
  void hashsign(std::unordered_map<std::string, FuncSignature> &elfsig, std::unordered_map<std::string, std::string> &sign2name);
  void findPatched(std::unordered_map<std::string, std::string> &elf, std::unordered_map<std::string, std::string> &cmp);
  void visit(Module *module);
  void visit(InitFunction *initFunction);
  void visit(FunctionList *functionlist) { recurse(functionlist); }
  void visit(DataRegionList *dataRegionList) { recurse(dataRegionList); }
  void visit(Function *function);
  void visit(Block *block);
  void visit(Instruction *instruction);
  void visit(DataRegion *dataRegion) { recurse(dataRegion); }
  void visit(DataSection *dataSection);
  void visit(DataVariable *dataVariable);
};
#endif
