#include <iostream>
#include "reversepatch.h"
#include "disasm/disassemble.h"
#include "instr/linked-x86_64.h"
#include "link.h"
#include "types.h"
#include "log/log.h"

// current goal
// to get the signature of function

void ReversePatch::visit(Function *function) {
  std::cout << "function name: " << function->getName() << "\n";
  Signature funcSign;
  funcSign.fsignature = "";
  recurse(function);
  std::cout << "fsign: " << funcSign.fsignature << "\n";
}

void ReversePatch::visit(Block *block) {
  //LOG(4, block->getName() << ":");
  recurse(block);
}

void ReversePatch::visit(Instruction *instruction) {
  InstructionSign instrsign;
  instruction->getSemantic()->accept(&instrsign);
}

void InstructionSign::visit(IsolatedInstruction *semantic) {
  // std::cout << "Isolated Instruction: ";
  //funcSign.fsignature += semantic->getAssembly()->getMnemonic();
  //std::cout << funcSign.fsignature << "\n";
}

void InstructionSign::visit(LinkedInstruction *semantic) {
  //std::cout << "Linked Instruction: ";
  //funcSign.fsignature += semantic->getAssembly()->getMnemonic();
}

void InstructionSign::visit(ControlFlowInstruction *semantic) {
  //std::cout << "ControlFlow Instruction: ";
  //funcSign.fsignature += semantic->getMnemonic();
}

#ifdef ARCH_X86_64
void InstructionSign::visit(DataLinkedControlFlowInstruction *semantic) {
  //std::cout << "Data Linked ControlFlow Instruction: ";
  //funcSign.fsignature += semantic->getAssembly()->getMnemonic();
}
#endif

void InstructionSign::visit(ReturnInstruction *semantic) {
  //std::cout << "Ret: ";
  //funcSign.fsignature += semantic->getAssembly()->getMnemonic();
}

void InstructionSign::visit(IndirectJumpInstruction *semantic) {
  //std::cout << "Indirect Jump Instruction: ";
  //funcSign.fsignature += semantic->getMnemonic();
}

void InstructionSign::visit(IndirectCallInstruction *semantic) {
  //std::cout << "Indirect call Instruction: ";
  //funcSign.fsignature += "CALL";
}

void InstructionSign::visit(StackFrameInstruction *semantic) {
  //std::cout << "stack frame Instruction: ";
  //funcSign.fsignature += semantic->getAssembly()->getMnemonic();
}

void InstructionSign::visit(LiteralInstruction *semantic) {
  //std::cout << "Literal Instruction: ";
  //funcSign.fsignature += semantic->getAssembly()->getMnemonic();
}

void InstructionSign::visit(LinkedLiteralInstruction *semantic) {
  //std::cout << "Linked literal Instruction: ";
  //funcSign.fsignature += semantic->getAssembly()->getMnemonic();
}
