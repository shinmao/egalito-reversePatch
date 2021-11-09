#include <iostream>
#include <string>
#include <algorithm>
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
  std::cout << "+===elfsign===+\n";
  for(auto it = elfsign.begin(); it != elfsign.end(); ++it) {
    std::cout << it->first << "\n";
    std::cout << "numBB: " << it->second.numBB << "\n";
    std::cout << "numInst: " << it->second.numInst << "\n";
    for(auto it_ = it->second.fq_mnemonic.begin(); it_ != it->second.fq_mnemonic.end(); ++it_) {
      std::cout << it_->first << ": " << it_->second << "; ";
    }
    for(auto it_ = it->second.fq_type.begin(); it_ != it->second.fq_type.end(); ++it_) {
      std::cout << it_->first << ": " << it_->second << "; ";
    }
    std::cout << "[";
    for(auto i : it->second.callee) std::cout << i << ", ";
    std::cout << "]\n";
    std::cout << "[";
    for(auto i : it->second.caller) std::cout << i << ", ";
    std::cout << "]\n";
  }
  std::cout << "+===cmpelfsign===+\n";
  for(auto it = cmpelfsign.begin(); it != cmpelfsign.end(); ++it) {
    std::cout << it->first << "\n";
    std::cout << "numBB: " << it->second.numBB << "\n";
    std::cout << "numInst: " << it->second.numInst << "\n";
    for(auto it_ = it->second.fq_mnemonic.begin(); it_ != it->second.fq_mnemonic.end(); ++it_) {
      std::cout << it_->first << ": " << it_->second << "; ";
    }
    for(auto it_ = it->second.fq_type.begin(); it_ != it->second.fq_type.end(); ++it_) {
      std::cout << it_->first << ": " << it_->second << "; ";
    }
    std::cout << "[";
    for(auto i : it->second.callee) std::cout << i << ", ";
    std::cout << "]\n";
    std::cout << "[";
    for(auto i : it->second.caller) std::cout << i << ", ";
    std::cout << "]\n";
  }
}

void ReversePatch::visit(Module *module) {
  //auto program = static_cast<Program *>(module->getParent());
  std::cout << "Compare module-[" << module->getName() << "] with module-[" << comparedModule->getName()
    << "]\n";
  recurse(module);
  elfsign = fsign;
  fsign.clear();

  recurse(comparedModule);
  cmpelfsign = fsign;
  fsign.clear();
  std::cout << "start compare here!!\n";
  compare();
}

void ReversePatch::visit(FunctionList *functionlist) {
  recurse(functionlist);
}

void ReversePatch::visit(Function *function) {
  // if function belongs to initFunctionList, then just skip
  if(dynamic_cast<InitFunction *>(function)) return;
  fs.funcname = function->getName();
  ControlFlowGraph cfg(function);
  // get num of basic block
  fs.numBB = cfg.getCount();
  recurse(function);
  std::unordered_map<std::string, int> freq_mnemonic;
  std::unordered_map<std::string, int> freq_type;
  for(auto &i : fs.mnemonic) freq_mnemonic[i]++;
  for(auto &i : fs.instType) freq_type[i]++;
  fs.fq_mnemonic = freq_mnemonic;
  fs.fq_type = freq_type;
  fsign[function->getName()] = fs;
}

void ReversePatch::visit(Block *block) {
  // get num of Instruction
  fs.numInst = block->getChildren()->getIterable()->getCount();
  recurse(block);
}

void ReversePatch::visit(Instruction *instruction) {
  // InstructionSign inssign;
  // instruction->getSemantic()->accept(&inssign);
  auto semantic = instruction->getSemantic();
  #ifdef ARCH_X86_64
  if(dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)) {
    fs.mnemonic.push_back(dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("DataLinkedCFI");
    std::cout << "DataLinkedCFI: " << dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
    return;
  }
  #endif
  if(dynamic_cast<IsolatedInstruction *>(semantic)) {
    // inherit SemanticImpl
    fs.mnemonic.push_back(dynamic_cast<IsolatedInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("Isolated");
  }
  else if (dynamic_cast<LinkedInstruction *>(semantic)) {
    fs.mnemonic.push_back(dynamic_cast<LinkedInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("Linked");
    std::cout << "Linked: " << dynamic_cast<LinkedInstruction *>(semantic)->getAssembly()->getMnemonic() << "\n";
  }
  else if (dynamic_cast<ReturnInstruction *>(semantic)) {
    fs.mnemonic.push_back(dynamic_cast<ReturnInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("Ret");
  }
  else if (dynamic_cast<IndirectCallInstruction *>(semantic)) {
    // inherit IsolatedInstruction
    fs.mnemonic.push_back(dynamic_cast<IndirectCallInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("IndirectCall");
    std::cout << "IndirectCall: " << dynamic_cast<IndirectCallInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
  else if (dynamic_cast<StackFrameInstruction *>(semantic)) {
    // most have stack frame, so we don't consider as signature
    fs.mnemonic.push_back(dynamic_cast<StackFrameInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("StackFrame");
  }
  else if(dynamic_cast<LiteralInstruction *>(semantic)) {
    // inherit SemanticImpl
    fs.mnemonic.push_back(dynamic_cast<LiteralInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("Literal");
    std::cout << "Literal: " << dynamic_cast<LiteralInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
  else if(dynamic_cast<LinkedLiteralInstruction *>(semantic)) {
    fs.mnemonic.push_back(dynamic_cast<LinkedLiteralInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("LinkedLiteral");
    std::cout << "LinkedLiteral: " << dynamic_cast<LinkedLiteralInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
  else if(dynamic_cast<ControlFlowInstruction *>(semantic)) {
    auto s = dynamic_cast<ControlFlowInstruction *>(semantic);
    fs.mnemonic.push_back(s->getMnemonic());
    fs.instType.push_back("CFI");
    std::cout << "ControlFlowInstruction: " << s->getMnemonic() << "\n";
    // get callee
    if(s->getMnemonic() == "callq") {
      auto link = s->getLink();
      if(!link) return;
      if(auto target = dynamic_cast<Function *>(&*link->getTarget())) {
        std::cout << "callee function name of " << instruction->getParent()->getParent()->getName() << ": "
          << target->getName() << "\n";
        if(target->getName() == instruction->getParent()->getParent()->getName()) {
          fs.callee.push_back("self");
        }else {
          fs.callee.push_back(target->getName());
        }
      }
      if(auto caller = s->getSource()) {
        std::cout << "caller function name of " << instruction->getParent()->getParent()->getName() << ": "
          << caller->getParent()->getParent()->getName() << "\n";
        if(caller->getParent()->getParent()->getName() == instruction->getParent()->getParent()->getName()) {
          fs.caller.push_back("self");
        }else {
          fs.caller.push_back(caller->getParent()->getParent()->getName());
        }
      }
    }
  }
  else if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
    // inherit IndirectControlFlowInstructionBase
    fs.mnemonic.push_back(dynamic_cast<IndirectJumpInstruction *>(semantic)->getMnemonic());
    fs.instType.push_back("IndirectJmp");
    std::cout << "IndirectJmp: " << dynamic_cast<IndirectJumpInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
}
