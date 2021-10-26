#ifndef EGALITO_PASS_REVERSEPATCH_H
#define EGALITO_PASS_REVERSEPATCH_H

#include "chunkpass.h"
#include "instr/visitor.h"
#include "instr/concrete.h"

class Signature {
public:
  std::string fsignature;
};

class ReversePatch : public ChunkPass {
public:
  std::string fsign;
  virtual ~ReversePatch() { std::cout << "Revdone\n"; }
  virtual void visit(Function *function);
  virtual void visit(Block *block);
  virtual void visit(Instruction *instruction);
};

class InstructionSign : public InstructionVisitor, public ReversePatch {
public:
  ~InstructionSign() { std::cout << "InstructionSign\n"; }
  void visit(IsolatedInstruction *semantic);
  void visit(LinkedInstruction *semantic);
  void visit(ControlFlowInstruction *semantic);
#ifdef ARCH_X86_64
  void visit(DataLinkedControlFlowInstruction *semantic);
#endif
  void visit(ReturnInstruction *semantic);
  void visit(IndirectJumpInstruction *semantic);
  void visit(IndirectCallInstruction *semantic);
  void visit(StackFrameInstruction *semantic);
  void visit(LiteralInstruction *semantic);
  void visit(LinkedLiteralInstruction *semantic);
};

#endif
