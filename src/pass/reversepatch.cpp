#include <iostream>
#include <string>
#include <algorithm>
// #include <openssl>
#include "reversepatch.h"
#include "disasm/disassemble.h"
#include "analysis/controlflow.h"
#include "instr/linked-x86_64.h"
#include "instr/assembly.h"
#include "link.h"
#include "types.h"
#include "log/log.h"

// current goal
// to get the signature of function

void ReversePatch::compare() {
  for(auto i = 0; i < elfsign.size(); ++i) {
    auto pos = std::find(cmpelfsign.begin(), cmpelfsign.end(), elfsign[i]);
    if(pos != cmpelfsign.end()) {
      // remove matched function pair
      elfsign.erase(elfsign.begin() + i);
      cmpelfsign.erase(pos);
    }
  }
  std::cout << "finish comparison\n";
  for(auto i : elfsign) std::cout << i << "\n";
  std::cout << "cmpelfsign\n";
  for(auto i : cmpelfsign) std::cout << i << "\n";
}

void ReversePatch::visit(Module *module) {
  auto program = static_cast<Program *>(module->getParent());
  std::cout << "Compare module-[" << module->getName() << "] with module-[" << comparedModule->getName()
    << "]\n";
  recurse(module);
  for(auto sig : fsign) { elfsign.push_back(sig); }
  std::cout << "For elfsign: " << elfsign[0] << "\n";
  fsign.clear();
  recurse(comparedModule);
  for(auto sig : fsign) { cmpelfsign.push_back(sig); }
  std::cout << "For cmpelfsign: " << cmpelfsign[0] << "\n";
  fsign.clear();
  std::cout << "start compare here!!\n";
  compare();
}

void ReversePatch::visit(FunctionList *functionlist) {
  recurse(functionlist);
  std::cout << "function list: " << fsign.size() << "\n";
}

void ReversePatch::visit(Function *function) {
  ControlFlowGraph cfg(function);
  // get num of basic block
  sign += std::to_string(cfg.getCount());
  recurse(function);
  std::cout << "function name: " << function->getName() << " with sign: " << sign << "\n";
  fsign.push_back(sign);
  sign = "";
}

void ReversePatch::visit(Block *block) {
  // get num of Instruction
  sign += std::to_string(block->getChildren()->getIterable()->getCount());
  recurse(block);
}

void ReversePatch::visit(Instruction *instruction) {
  // InstructionSign inssign;
  // instruction->getSemantic()->accept(&inssign);
  auto semantic = instruction->getSemantic();
  #ifdef ARCH_X86_64
  if(dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)) {
    sign += dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)->getAssembly()->getMnemonic();
    std::cout << "operand: " << dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
    return;
  }
  #endif
  if(dynamic_cast<IsolatedInstruction *>(semantic)) {
    std::vector<std::string> s;
    // inherit SemanticImpl
    sign += dynamic_cast<IsolatedInstruction *>(semantic)->getAssembly()->getMnemonic();
    auto operand = dynamic_cast<IsolatedInstruction *>(semantic)->getAssembly()->getOpStr();
  }
  else if (dynamic_cast<LinkedInstruction *>(semantic)) {
    std::string signstr = dynamic_cast<LinkedInstruction *>(semantic)->getAssembly()->getMnemonic();
    sign += signstr;
    auto start = 0;
    auto end = signstr.find("(", start);
    std::cout << "offset to src reg: " << signstr.substr(start, end - start) << "\n";
    start = end + 1;
    end = signstr.find(")", start);
    std::cout << "src reg: " << signstr.substr(start, end - start) << "\n";
    start = end + 2;
    std::cout << "dest reg: " << start << "\n";
  }
  else if (dynamic_cast<ReturnInstruction *>(semantic)) {
    sign += dynamic_cast<ReturnInstruction *>(semantic)->getAssembly()->getMnemonic();
  }
  else if (dynamic_cast<IndirectCallInstruction *>(semantic)) {
    // inherit IsolatedInstruction
    sign += dynamic_cast<IndirectCallInstruction *>(semantic)->getAssembly()->getMnemonic();
    std::cout << "operand: " << dynamic_cast<IndirectCallInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
  else if (dynamic_cast<StackFrameInstruction *>(semantic)) {
    // most have stack frame, so we don't consider as signature
    sign += dynamic_cast<StackFrameInstruction *>(semantic)->getAssembly()->getMnemonic();
  }
  else if(dynamic_cast<LiteralInstruction *>(semantic)) {
    // inherit SemanticImpl
    sign += dynamic_cast<LiteralInstruction *>(semantic)->getAssembly()->getMnemonic();
    std::cout << "operand: " << dynamic_cast<LiteralInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
  else if(dynamic_cast<LinkedLiteralInstruction *>(semantic)) {
    sign += dynamic_cast<LinkedLiteralInstruction *>(semantic)->getAssembly()->getMnemonic();
    std::cout << "operand: " << dynamic_cast<LinkedLiteralInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
  else if(dynamic_cast<ControlFlowInstruction *>(semantic)) {
    auto s = dynamic_cast<ControlFlowInstruction *>(semantic);
    sign += s->getMnemonic();
    // get callee
    if(s->getMnemonic() == "callq") {
      auto link = s->getLink();
      if(!link) return;
      if(auto target = dynamic_cast<Function *>(&*link->getTarget())) {
        std::cout << "callee function name: " << target->getName() << "\n";
      }
    }
  }
  else if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
    // inherit IndirectControlFlowInstructionBase
    sign += dynamic_cast<IndirectJumpInstruction *>(semantic)->getMnemonic();
    std::cout << "operand: " << dynamic_cast<IndirectJumpInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
}
