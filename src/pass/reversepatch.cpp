#include <iostream>
#include <string>
#include <algorithm>
#include "reversepatch.h"
#include "findsyscalls.h"
#include "disasm/disassemble.h"
#include "analysis/controlflow.h"
#include "instr/linked-x86_64.h"
#include "instr/assembly.h"
#include "link.h"
#include "types.h"
#include "log/log.h"

// current goal
// to get the signature of function

void ReversePatch::compareLog() {
  // this function is used to print out signatures of two binaries
  std::cout << "+===================elfsign====================+\n";
  for(auto it = elfsign.begin(); it != elfsign.end(); ++it) {
    std::cout << it->first << "\n";
    std::cout << "numBB: " << it->second.numBB << "\n";
    std::cout << "numInst: " << it->second.numInst << "\n";
    std::cout << "numSyscall: " << it->second.numSyscall << "\n";
    std::cout << "\nWho is called by me: [";
    for(auto i : it->second.callee) std::cout << i << ", ";
    std::cout << "]\n";
    std::cout << "Who calls me: [";
    for(auto i : it->second.caller) std::cout << i << ", ";
    std::cout << "]\n";
  }
  std::cout << "+====================cmpelfsign====================+\n";
  for(auto it = cmpelfsign.begin(); it != cmpelfsign.end(); ++it) {
    std::cout << it->first << "\n";
    std::cout << "numBB: " << it->second.numBB << "\n";
    std::cout << "numInst: " << it->second.numInst << "\n";
    std::cout << "numSyscall: " << it->second.numSyscall << "\n";
    std::cout << "\nWho is called by me: [";
    for(auto i : it->second.callee) std::cout << i << ", ";
    std::cout << "]\n";
    std::cout << "Who calls me: [";
    for(auto i : it->second.caller) std::cout << i << ", ";
    std::cout << "]\n";
  }
}

void ReversePatch::mergeTable(std::unordered_map<std::string, FuncSignature> &elfsig) {
  std::cout << "merging tables from two binaries\n";
  for(auto i = elfsig.begin(); i != elfsig.end(); ++i) {
    for(auto it = mnemonic_set.begin(); it != mnemonic_set.end(); ++it) {
      i->second.fq_mnemonic.push_back(std::count(i->second.mnemonic.begin(), i->second.mnemonic.end(), *it));
    }

    for(auto it = type_set.begin(); it != type_set.end(); ++it) {
      i->second.fq_type.push_back(std::count(i->second.instType.begin(), i->second.instType.end(), *it));
    }

    for(auto it = calle_set.begin(); it != calle_set.end(); ++it) {
      i->second.fq_calle.push_back(std::count(i->second.callee.begin(), i->second.callee.end(), *it));
    }

    for(auto it = plt_set.begin(); it != plt_set.end(); ++it) {
      i->second.fq_callplt.push_back(std::count(i->second.callplt.begin(), i->second.callplt.end(), *it));
    }
  }
}

void ReversePatch::hashsign(std::unordered_map<std::string, FuncSignature> &elfsig, std::unordered_map<std::string, std::string> &sign2name) {
  // [ numBB | numInst | numSyscall | fq_mnemonic | fq_type | fq_calle | fq_callplt ]
  std::cout << "start working on generating hash for two binaries\n";
  for(auto i = elfsig.begin(); i != elfsig.end(); ++i) {
    std::string res = "";
    res += std::to_string(i->second.numBB);
    res += std::to_string(i->second.numInst);
    res += std::to_string(i->second.numSyscall);
    for(auto mne : i->second.fq_mnemonic) {
      res += std::to_string(mne);
    }
    for(auto type : i->second.fq_type) {
      res += std::to_string(type);
    }
    for(auto calle : i->second.fq_calle) {
      res += std::to_string(calle);
    }
    for(auto plt : i->second.fq_callplt) {
      res += std::to_string(plt);
    }
    i->second.signature = res;
    // map hash sign to function name in another map elf/cmp
    sign2name[res] = i->second.funcname;
  }
  std::cout << "consider_visiting: " << elfsig["consider_visiting"].signature << "\n";
  std::cout << "find: " << elfsig["find"].signature << "\n";
  std::cout << "===================\n";
}

void ReversePatch::findPatched(std::unordered_map<std::string, std::string> &elf, std::unordered_map<std::string, std::string> &cmp) {
  std::cout << "finding patched function in elf:\n";
  for(auto i = elf.begin(); i != elf.end(); ++i) {
    if(cmp.count(i->first) == 0) {
      std::cout << i->second << " function is patched\n";
    }
  }
  std::cout << "===================\n";
}

void ReversePatch::visit(Module *module) {
  auto program = static_cast<Program *>(module->getParent());
  std::cout << "Compare module-[" << module->getName() << "] with module-[" << comparedModule->getName()
    << "]\n";
  recurse(module->getInitFunctionList());
  recurse(module->getDataRegionList());
  recurse(module);
  elfsign = fsign;
  fsign.clear();
  initFunctionList.clear();

  recurse(comparedModule->getInitFunctionList());
  recurse(comparedModule->getDataRegionList());
  recurse(comparedModule);
  cmpelfsign = fsign;
  fsign.clear();
  initFunctionList.clear();

  //compareLog();
  mergeTable(elfsign);
  mergeTable(cmpelfsign);

  hashsign(elfsign, elf);
  hashsign(cmpelfsign, cmp);

  findPatched(elf, cmp);
  findPatched(cmp, elf);
}

void ReversePatch::visit(InitFunction *initFunction) {
  std::cout << "Init Function: " << initFunction->getName() << "\n";
  initFunctionList.push_back(initFunction->getName());
}

void ReversePatch::visit(Function *function) {
  // if function belongs to initFunctionList, then just skip
  if(std::find(initFunctionList.begin(), initFunctionList.end(), function->getName()) != initFunctionList.end()) {
	  std::cout << function->getName() << " belongs to initfunction\n";
	  return;
  }
  std::cout << "+================" << function->getName() << "================+\n";
  // find number of syscall based on each function
  FindSyscalls findSyscalls;
  function->accept(&findSyscalls);
  auto list = findSyscalls.getNumberMap();
  for(auto it : list) {
	  auto syscallInstr = it.first;
	  auto syscallValues = it.second;
	  // syscall are unique for single instr
	  // but not unique in multiple instr
	  std::cout << "syscall: " << syscallValues.size() << "\n";
	  fs.numSyscall += syscallValues.size();
  }
  std::cout << "num of syscall: " << fs.numSyscall << "\n";

  fs.funcname = function->getName();
  ControlFlowGraph cfg(function);
  // get num of basic block
  fs.numBB = cfg.getCount();
  // recurse means after finish single function
  recurse(function);

  fsign[function->getName()] = fs;
  fs = FuncSignature();
}

void ReversePatch::visit(Block *block) {
  // get num of Instruction
  // recurse means after finish one bb
  recurse(block);
  fs.numInst += inst_counter;
  inst_counter = 0;
}

void ReversePatch::visit(Instruction *instruction) {
  // InstructionSign inssign;
  // instruction->getSemantic()->accept(&inssign);
  inst_counter++;
  auto semantic = instruction->getSemantic();
  #ifdef ARCH_X86_64
  if(dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)) {
    fs.mnemonic.push_back(dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)->getAssembly()->getMnemonic());
    mnemonic_set.insert(dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("DataLinkedCFI");
    type_set.insert("DataLinkedCFI");
    std::cout << "DataLinkedCFI: " << dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
    return;
  }
  #endif
  if(dynamic_cast<IsolatedInstruction *>(semantic)) {
    // inherit SemanticImpl
    fs.mnemonic.push_back(dynamic_cast<IsolatedInstruction *>(semantic)->getAssembly()->getMnemonic());
    mnemonic_set.insert(dynamic_cast<IsolatedInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("Isolated");
    type_set.insert("Isolated");
  }
  else if (dynamic_cast<LinkedInstruction *>(semantic)) {
    fs.mnemonic.push_back(dynamic_cast<LinkedInstruction *>(semantic)->getAssembly()->getMnemonic());
    mnemonic_set.insert(dynamic_cast<LinkedInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("Linked");
    type_set.insert("Linked");
    std::cout << "Linked: " << dynamic_cast<LinkedInstruction *>(semantic)->getAssembly()->getMnemonic();
    std::cout << " with target: " << dynamic_cast<LinkedInstruction *>(semantic)->getLink()->getTargetAddress() << " ";
    std::cout << "DispSize: " << dynamic_cast<LinkedInstruction *>(semantic)->getDispSize() << " ";
    std::cout << "DispOffset: " << dynamic_cast<LinkedInstruction *>(semantic)->getDispOffset() << "\n";
  }
  else if (dynamic_cast<ReturnInstruction *>(semantic)) {
    fs.mnemonic.push_back(dynamic_cast<ReturnInstruction *>(semantic)->getAssembly()->getMnemonic());
    mnemonic_set.insert(dynamic_cast<ReturnInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("Ret");
    type_set.insert("Ret");
  }
  else if (dynamic_cast<IndirectCallInstruction *>(semantic)) {
    // inherit IsolatedInstruction
    fs.mnemonic.push_back(dynamic_cast<IndirectCallInstruction *>(semantic)->getAssembly()->getMnemonic());
    mnemonic_set.insert(dynamic_cast<IndirectCallInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("IndirectCall");
    type_set.insert("IndirectCall");
    std::cout << "IndirectCall: " << dynamic_cast<IndirectCallInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
  else if (dynamic_cast<StackFrameInstruction *>(semantic)) {
    // most have stack frame, so we don't consider as signature
    fs.mnemonic.push_back(dynamic_cast<StackFrameInstruction *>(semantic)->getAssembly()->getMnemonic());
    mnemonic_set.insert(dynamic_cast<StackFrameInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("StackFrame");
    type_set.insert("StackFrame");
  }
  else if(dynamic_cast<LiteralInstruction *>(semantic)) {
    // inherit SemanticImpl
    fs.mnemonic.push_back(dynamic_cast<LiteralInstruction *>(semantic)->getAssembly()->getMnemonic());
    mnemonic_set.insert(dynamic_cast<LiteralInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("Literal");
    type_set.insert("Literal");
    std::cout << "Literal: " << dynamic_cast<LiteralInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
  else if(dynamic_cast<LinkedLiteralInstruction *>(semantic)) {
    fs.mnemonic.push_back(dynamic_cast<LinkedLiteralInstruction *>(semantic)->getAssembly()->getMnemonic());
    mnemonic_set.insert(dynamic_cast<LinkedLiteralInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("LinkedLiteral");
    type_set.insert("LinkedLiteral");
    std::cout << "LinkedLiteral: " << dynamic_cast<LinkedLiteralInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
  else if(dynamic_cast<ControlFlowInstruction *>(semantic)) {
    auto s = dynamic_cast<ControlFlowInstruction *>(semantic);
    fs.mnemonic.push_back(s->getMnemonic());
    mnemonic_set.insert(s->getMnemonic());
    fs.instType.push_back("CFI");
    type_set.insert("CFI");
    std::cout << "ControlFlowInstruction: " << s->getMnemonic() << "\n";
    // get callee
    auto link = s->getLink();
    if(!link) return;
    if(auto target = dynamic_cast<Function *>(&*link->getTarget())) {
      std::cout << "callee function name of " << instruction->getParent()->getParent()->getName() << ": "
        << target->getName() << "\n";
      if(target->getName() == instruction->getParent()->getParent()->getName()) {
        fs.callee.push_back("self");
      }else {
        fs.callee.push_back(target->getName());
        calle_set.insert(target->getName());
      }
    }
    // get caller
    if(auto caller = s->getSource()) {
      std::cout << "caller function name of " << instruction->getParent()->getParent()->getName() << ": "
        << caller->getParent()->getParent()->getName() << "\n";
      if(caller->getParent()->getParent()->getName() == instruction->getParent()->getParent()->getName()) {
        fs.caller.push_back("self");
      }else {
        fs.caller.push_back(caller->getParent()->getParent()->getName());
      }
    }
    // get called@plt
    if(auto plt = dynamic_cast<PLTTrampoline *>(&*link->getTarget())) {
      std::cout << "call plt: " << plt->getName() << "\n";
      fs.callplt.push_back(plt->getName());
      plt_set.insert(plt->getName());
    }
  }
  else if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
    // inherit IndirectControlFlowInstructionBase
    fs.mnemonic.push_back(dynamic_cast<IndirectJumpInstruction *>(semantic)->getMnemonic());
    mnemonic_set.insert(dynamic_cast<IndirectJumpInstruction *>(semantic)->getAssembly()->getMnemonic());
    fs.instType.push_back("IndirectJmp");
    type_set.insert("IndirectJmp");
    std::cout << "IndirectJmp: " << dynamic_cast<IndirectJumpInstruction *>(semantic)->getAssembly()->getOpStr() << "\n";
  }
}

void ReversePatch::visit(DataSection *dataSection) {
  std::cout << "Visiting " << dataSection->getName() << "\n";
  for(auto var : CIter::children(dataSection)) {
     if(!var->getDest()) {
	     continue;
     }
     auto target = var->getDest()->getTarget();
     std::cout << "var: " << var->getAddress();
     if(target) {
	     std::cout << " --> " << target->getName() << "\n";
     }
  }
  for(auto var : dataSection->getGlobalVariables()) {
     std::cout << "global var: " << var->getName() << " with size: " << var->getSize() << " with address: " << var->getAddress() << "\n";
  }
}

void ReversePatch::visit(DataVariable *dataVariable) {
  std::cout << "data variable at " << dataVariable->getAddress();
  auto target = dataVariable->getDest() ? dataVariable->getDest()->getTarget() : nullptr;
  if(target) {
    std::cout << " --> " << target->getName() << "\n";
  }else {
    std::cout << "\n";
  }
}
//
// void ReversePatch::visit(GlobalVariable *globalVariable) {
//   std::cout << "global variable at " << globalVariable->getAddress() << "\n";
// }
