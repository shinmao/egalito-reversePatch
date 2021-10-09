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
      std::cout << "[block] visiting first block of main function...\n";

      auto insertpoint = block->getChildren()->getIterable()->get(0);
      ChunkMutator mutator(block);

      mutator.insertBefore(insertpoint, Disassemble::instruction({0xc7, 0x45, 0xf4, 0x00, 0x00, 0x00, 0x00}));
      mutator.insertBefore(insertpoint, Disassemble::instruction({0xeb, 0x0e}));
      mutator.insertBefore(insertpoint, Disassemble::instruction({0x8b, 0x45, 0x0c}));
      mutator.insertBefore(insertpoint, Disassemble::instruction({0x48, 0x98}));
      mutator.insertBefore(insertpoint, Disassemble::instruction({0xc6, 0x44, 0x05, 0xe0, 0x30}));
      mutator.insertBefore(insertpoint, Disassemble::instruction({0x83, 0x45, 0xc, 0x01}));
      // mov 0xc(%rbp),%eax
      mutator.insertBefore(insertpoint, Disassemble::instruction({0x8b, 0x45, 0x0c}));
      mutator.insertBefore(insertpoint, Disassemble::instruction({0x83, 0xf8, 0x1f}));
      // jmp to b2
      mutator.insertBefore(insertpoint, Disassemble::instruction({0x76, 0xea}));
    }
    recurse(block);
}

void ReversePatch::extendstack(Function *func, size_t extendSize) {
  // extend stack size of single function
  StackExtendPass extender(extendSize);
  func->accept(&extender);
}
