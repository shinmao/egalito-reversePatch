#include <iostream>
#include <string>
#include <algorithm>
#include <fstream>
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

void ReversePatch::writedata(std::string filename, std::unordered_map<std::string, std::vector<std::vector<float> > > &elf, std::unordered_map<std::string, std::vector<std::vector<float> > > &cmp) {
  std::ofstream data ("/home/rafael/Desktop/" + filename + "/vector.txt");
  if(data.is_open()) {
	  data << "main======================\n";
	  for(auto i = elf.begin(); i != elf.end(); ++i) {
		  data << "Main-Function: " << i->first << "\n";
		  data << "Syscall: " << std::to_string(i->second[0][0]) << "\n";
		  data << "Opcode: ";
		  for(auto j = i->second[1].begin(); j != i->second[1].end(); ++j) data << std::to_string(*j) << " ";
		  data << "\nType: ";
		  for(auto j = i->second[2].begin(); j != i->second[2].end(); ++j) data << std::to_string(*j) << " ";
	      data << "\nCallee: ";
	      for(auto j = i->second[3].begin(); j != i->second[3].end(); ++j) data << std::to_string(*j) << " ";
	      data << "\nPLT: ";
	      for(auto j = i->second[4].begin(); j != i->second[4].end(); ++j) data << std::to_string(*j) << " ";
          data << "\n";
	  }
	  data << "cmp=======================\n";
      for(auto i = cmp.begin(); i != cmp.end(); ++i) {
		  if(i->first == ref_funcname) {
			  data << "Matched-Function: " << i->first << "\n";
		  } else {
			  data << "Function: " << i->first << "\n";
		  }
		  data << "Syscall: " << std::to_string(i->second[0][0]) << "\n";
		  data << "Opcode: ";
		  for(auto j = i->second[1].begin(); j != i->second[1].end(); ++j) data << std::to_string(*j) << " ";
		  data << "\nType: ";
		  for(auto j = i->second[2].begin(); j != i->second[2].end(); ++j) data << std::to_string(*j) << " ";
	      data << "\nCallee: ";
	      for(auto j = i->second[3].begin(); j != i->second[3].end(); ++j) data << std::to_string(*j) << " ";
	      data << "\nPLT: ";
	      for(auto j = i->second[4].begin(); j != i->second[4].end(); ++j) data << std::to_string(*j) << " ";
          data << "\n";
	  }
	  data.close();
  }
  else std::cout << "Unable to open the file";
}

void ReversePatch::compareLog() {
  // this function is used to print out signatures of two binaries
  // single function in elf
  std::cout << "Print out hash signatures for two binaries\n For reference function: \n";
  for(auto i = elf.begin(); i != elf.end(); ++i) {
	  std::cout << "For function " << i->first << ":\n";
	  std::cout << "number of syscall: " << std::to_string(i->second[0][0]) << "\nopcode: [ ";
	  for(auto j = i->second[1].begin(); j != i->second[1].end(); ++j) {
		  std::cout << std::to_string(*j) << " ";
	  }
	  std::cout << "]\ntype: [ ";
	  for(auto j = i->second[2].begin(); j != i->second[2].end(); ++j) {
		  std::cout << std::to_string(*j) << " ";
	  }
	  std::cout << "]\ncallee: [ ";
	  for(auto j = i->second[3].begin(); j != i->second[3].end(); ++j) {
		  std::cout << std::to_string(*j) << " ";
	  }
	  std::cout << "]\nplt: [ ";
	  for(auto j = i->second[4].begin(); j != i->second[4].end(); ++j) {
		  std::cout << std::to_string(*j) << " ";
	  }
      std::cout << "]\n";
  }
  std::cout << "=======================================================================\n";
  // all functions in cmp
  for(auto i = cmp.begin(); i != cmp.end(); ++i) {
	  std::cout << "For function " << i->first << ":\n";
	  std::cout << "number of syscall: " << std::to_string(i->second[0][0]) << "\nopcode: [ ";
	  for(auto j = i->second[1].begin(); j != i->second[1].end(); ++j) {
		  std::cout << std::to_string(*j) << " ";
	  }
	  std::cout << "]\ntype: [ ";
	  for(auto j = i->second[2].begin(); j != i->second[2].end(); ++j) {
		  std::cout << std::to_string(*j) << " ";
	  }
	  std::cout << "]\ncallee: [ ";
	  for(auto j = i->second[3].begin(); j != i->second[3].end(); ++j) {
		  std::cout << std::to_string(*j) << " ";
	  }
	  std::cout << "]\nplt: [ ";
	  for(auto j = i->second[4].begin(); j != i->second[4].end(); ++j) {
		  std::cout << std::to_string(*j) << " ";
	  }
      std::cout << "]\n";
  }
}

void ReversePatch::mergeTable(std::unordered_map<std::string, FuncSignature> &elfsig) {
  std::cout << "merging tables from two binaries\n";
  for(auto i = elfsig.begin(); i != elfsig.end(); ++i) {
	std::cout << "number of instruction is " << i->second.numInst << "\n";
    for(auto it = mnemonic_set.begin(); it != mnemonic_set.end(); ++it) {
	  // opcode would show with percentage
	  float per_mnemonic = static_cast<float>(std::count(i->second.mnemonic.begin(), i->second.mnemonic.end(), *it)) / static_cast<float>(i->second.numInst);
      i->second.fq_mnemonic.push_back(per_mnemonic);
    }

    for(auto it = type_set.begin(); it != type_set.end(); ++it) {
      // instruction type would show with percentage
	  float per_type = static_cast<float>(std::count(i->second.instType.begin(), i->second.instType.end(), *it)) / static_cast<float>(i->second.numInst);
	  i->second.fq_type.push_back(per_type);
    }

    for(auto it = calle_set.begin(); it != calle_set.end(); ++it) {
	  // callee function would show with count
	  float cnt_callee = static_cast<float>(std::count(i->second.callee.begin(), i->second.callee.end(), *it));
      i->second.fq_calle.push_back(cnt_callee);
    }

    for(auto it = plt_set.begin(); it != plt_set.end(); ++it) {
	  // plt function would show with count
	  float cnt_plt = static_cast<float>(std::count(i->second.callplt.begin(), i->second.callplt.end(), *it));
      i->second.fq_callplt.push_back(cnt_plt);
    }
  }
}

void ReversePatch::hashsign(std::unordered_map<std::string, FuncSignature> &elfsig, std::unordered_map<std::string, std::vector<std::vector<float> > > &name2sign) {
  // [ numSyscall | fq_mnemonic | fq_type | fq_calle | fq_callplt ] put into name2sign 
  std::cout << "start working on generating hash for two binaries\n";
  for(auto i = elfsig.begin(); i != elfsig.end(); ++i) {
    std::vector<std::vector<float> > res;
	std::vector<float> sc{ i->second.numSyscall };
    res.push_back(sc);
	res.push_back( i->second.fq_mnemonic );
	res.push_back( i->second.fq_type );
	res.push_back( i->second.fq_calle );
	res.push_back( i->second.fq_callplt );
    i->second.signature = res;
    // map hash sign to function name in another map elf/cmp
    name2sign[i->second.funcname] = res;
  }
  std::cout << "===================\n";
}

void ReversePatch::findPatched(std::unordered_map<std::string, std::string> &elf, std::unordered_map<std::string, std::string> &cmp) {
  std::cout << "finding similar function in elf:\n";
  for(auto i = elf.begin(); i != elf.end(); ++i) {
    if(cmp.count(i->first) > 0) {
      std::cout << i->second << " function is found\n";
    }
  }
  std::cout << "===================\n";
}

void ReversePatch::visit(Module *module) {
  auto program = static_cast<Program *>(module->getParent());
  std::cout << "Compare module-[" << module->getName() << "] with module-[" << comparedModule->getName()
    << "] on function: " << ref_funcname << "()\n";
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
  /**
  std::cout << "================================\n";
  for(auto i : mnemonic_set) { std::cout << i << " "; }
  std::cout << "\n";
  for(auto i : type_set) { std::cout << i << " "; }
  std::cout << "\n";
  for(auto i : calle_set) { std::cout << i << " "; }
  std::cout << "\n";
  for(auto i : plt_set) { std::cout << i << " "; }
  std::cout << "\n===============================\n";**/

  mergeTable(elfsign);
  mergeTable(cmpelfsign);

  hashsign(elfsign, elf);
  hashsign(cmpelfsign, cmp);

  // print out single function in elf and all functions in cmp
  //compareLog();

  writedata(outputlog, elf, cmp);
  //findPatched(elf, cmp);
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
  std::string mod_name = dynamic_cast<Module *>(function->getParent()->getParent())->getName();
  if(mod_name == "module-(executable)") {
	  // if functions belongs to module-(executable), then only check reference function
	  if(function->getName() != ref_funcname) return;
  }
  std::cout << "+================" << function->getName() << "================+\n";
  // find number of syscall based on each function
  /** temporarily close the function of tracing syscall
  findsyscalls findsyscalls;
  function->accept(&findSyscalls);
  auto list = findSyscalls.getNumberMap();
  for(auto it : list) {
	  auto syscallInstr = it.first;
	  auto syscallValues = it.second;
	  // syscall are unique for single instr
	  // but not unique in multiple instr
	  std::cout << "syscall: " << syscallValues.size() << "\n";
	  fs.numSyscall += syscallValues.size();
  }**/
  fs.numSyscall = 0;
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
