#include <iostream>
// #include <openssl>
#include "reversepatch.h"
#include "disasm/disassemble.h"
#include "instr/linked-x86_64.h"
#include "link.h"
#include "types.h"
#include "log/log.h"

// current goal
// to get the signature of function

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
}

void ReversePatch::visit(FunctionList *functionlist) {
  recurse(functionlist);
  std::cout << "function list: " << fsign.size() << "\n";
}

void ReversePatch::visit(Function *function) {
  recurse(function);
  std::cout << "function name: " << function->getName() << " with sign: " << sign << "\n";
  fsign.push_back(sign);
  sign = "";
}

void ReversePatch::visit(Block *block) {
  //LOG(4, block->getName() << ":");
  recurse(block);
}

void ReversePatch::visit(Instruction *instruction) {
  // InstructionSign inssign;
  // instruction->getSemantic()->accept(&inssign);
  auto semantic = instruction->getSemantic();
  #ifdef ARCH_X86_64
  if(dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)) {
    sign += dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)->getAssembly()->getMnemonic();
    return;
  }
  #endif
  if(dynamic_cast<IsolatedInstruction *>(semantic)) {
    sign += dynamic_cast<IsolatedInstruction *>(semantic)->getAssembly()->getMnemonic();
  }
  else if (dynamic_cast<LinkedInstruction *>(semantic)) {
    sign += dynamic_cast<LinkedInstruction *>(semantic)->getAssembly()->getMnemonic();
  }
  else if (dynamic_cast<ReturnInstruction *>(semantic)) {
    sign += dynamic_cast<ReturnInstruction *>(semantic)->getAssembly()->getMnemonic();
  }
  else if (dynamic_cast<IndirectCallInstruction *>(semantic)) {
    sign += dynamic_cast<IndirectCallInstruction *>(semantic)->getAssembly()->getMnemonic();
  }
  else if (dynamic_cast<StackFrameInstruction *>(semantic)) {
    sign += dynamic_cast<StackFrameInstruction *>(semantic)->getAssembly()->getMnemonic();
  }
  else if(dynamic_cast<LiteralInstruction *>(semantic)) {
    sign += dynamic_cast<LiteralInstruction *>(semantic)->getAssembly()->getMnemonic();
  }
  else if(dynamic_cast<LinkedLiteralInstruction *>(semantic)) {
    sign += dynamic_cast<LinkedLiteralInstruction *>(semantic)->getAssembly()->getMnemonic();
  }
  else if(dynamic_cast<ControlFlowInstruction *>(semantic)) {
    sign += dynamic_cast<ControlFlowInstruction *>(semantic)->getMnemonic();
  }
  else if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
    sign += dynamic_cast<IndirectJumpInstruction *>(semantic)->getMnemonic();
  }
}
