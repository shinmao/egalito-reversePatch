#include <iostream>
#include <sstream>
#include "reversepatch.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "analysis/frametype.h"
#include "stackextend.h"
#include "link.h"

void ReversePatch::visit(Function *function) {
  if (function->getName() == "main") {
    if (extendsize != 0x0) {
      extendstack(function, extendsize);
    }
    /**
    auto block3 = function->getChildren()->getIterable()->get(2);
    auto block4 = function->getChildren()->getIterable()->get(3);
    auto block5 = function->getChildren()->getIterable()->get(4);
    target_func.push_back("main");
    rmBlk.push_back(block3);
    target_func.push_back("main");
    rmBlk.push_back(block4);
    target_func.push_back("main");
    rmBlk.push_back(block5);
  }

  std::cout << "[function] visiting...\n";
  for (int i = 0; i < target_func.size(); i++) {
    if(function->getName() == target_func[i]) {
      std::cout << "[function] visiting " << function->getName() << "...\n";
      ChunkMutator mutator(function);
      if (rmBlk.size() > i) {
        mutator.remove(rmBlk[i]);
      }
      if (insbeforeBlk.size() > i) {
        mutator.insertBefore(insbeforeB[i], insbeforeBlk[i]);
      }
    }**/
    auto block = function->getChildren()->getIterable()->get(2);
    ChunkMutator mutator(function);
    mutator.insertBefore(block, Disassemble::instruction({0xc7, 0x45, 0xf4, 0x00, 0x00, 0x00, 0x00}));
  }
  recurse(function);
}

void ReversePatch::visit(Block *block) {
    std::cout << "[block] visiting block of main function...\n";
    if (block->getName() == "main/bb+0") {
      /**
      std::cout << "[block] visiting first block of main function...\n";
      auto parent = dynamic_cast<Function *>(block->getParent());
      FrameType frameType(parent);
      auto prologueEnd = frameType.getSetSPInstr();

      // change stack size from 0x30 to 0x20
      ChunkMutator mutator(block);
      mutator.insertBefore(prologueEnd, Disassemble::instruction({0x48, 0x83, 0xec, 0x20}));
      // remove original prologue end
      mutator.remove(prologueEnd);**/
    }
    else if (block->getName() == "main/bb+35") {
      /**
      std::cout << "[block] visiting second block of main function...\n";
      auto instr3 = block->getChildren()->getIterable()->get(2);
      ChunkMutator mutator(block);
      mutator.insertBefore(instr3, Disassemble::instruction({0x48, 0x8d, 0x45, 0xe0}));
      // remove original
      mutator.remove(instr3);**/
    }
    else if (block->getName() == "main/bb+66") {
      /**
      std::cout << "[block] visiting first block of main function...\n";
      ChunkMutator mutator(block);

      auto b1 = Disassemble::instruction({0xc7, 0x45, 0xf4, 0x00, 0x00, 0x00, 0x00});
      auto b2 = Disassemble::instruction({0x8b, 0x45, 0x0c, 0x48, 0x98,
        0xc6, 0x44, 0x05, 0xe0, 0x30, 0x83, 0x45, 0xc, 0x01});
      // mov 0xc(%rbp),%eax
      auto b3 = Disassemble::instruction({0x8b, 0x45, 0x0c, 0x83, 0xf8, 0x1f});
      // jmp to b2
      auto b3jbe = new Instruction();
      auto b3jbesem = new ControlFlowInstruction(X86_INS_JBE, b3jbe, "\x0f\x86", 4);
      b3jbesem->setLink(new NormalLink(b2, Link::SCOPE_INTERNAL_JUMP));
      b3jbe->setSemantic(b3jbesem);
      // jmp to b3
      auto b1jmp = new Instruction();
      auto b1jmpsem = new ControlFlowInstruction(X86_INS_JMP, b1jmp, "\xe9", 4);
      b1jmpsem->setLink(new NormalLink(b3, Link::SCOPE_INTERNAL_JUMP));
      b1jmp->setSemantic(b1jmpsem);
      // put commands into vector
      inserted.push_back(b1);
      inserted.push_back(b1jmp);
      inserted.push_back(b2);
      inserted.push_back(b3);
      inserted.push_back(b3jbe);
      // insert before block
      mutator.insertBefore(block->getChildren()->getIterable()->get(2), b1);
      **/
    }
    //recurse(block);
}

void ReversePatch::extendstack(Function *func, size_t extendSize) {
  // extend stack size of single function
  StackExtendPass extender(extendSize);
  func->accept(&extender);
}
