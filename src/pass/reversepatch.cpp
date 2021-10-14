#include <iostream>
#include <sstream>
#include "reversepatch.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "analysis/frametype.h"
#include "instr/linked-x86_64.h"
#include "stackextend.h"
#include "link.h"
#include "types.h"

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
      auto instr1 = Disassemble::instruction({0xc7, 0x45, 0x0c, 0x00, 0x00, 0x00, 0x00});
      auto instr3 = Disassemble::instruction({0x8b, 0x45, 0x0c});
      auto instr4 = Disassemble::instruction({0x48, 0x98});
      auto instr5 = Disassemble::instruction({0xc6, 0x44, 0x05, 0xe0, 0x30});
      auto instr6 = Disassemble::instruction({0x83, 0x45, 0xc, 0x01});
      auto instr7 = Disassemble::instruction({0x8b, 0x45, 0x0c});
      auto instr8 = Disassemble::instruction({0x83, 0xf8, 0x1f});

      auto jmp2 = new Instruction();
      // the last parameter means the number of padding bytes
      auto jmpSem = new ControlFlowInstruction(X86_INS_JMP, jmp2, "\xeb\x0e", "jmp", 0);
      jmpSem->setLink(new NormalLink(instr7, Link::SCOPE_EXTERNAL_JUMP));
      jmp2->setSemantic(jmpSem);

      auto jbe9 = new Instruction();
      auto jbeSem = new ControlFlowInstruction(X86_INS_JBE, jbe9, "\x76\xea", "jbe", 0);
      jbeSem->setLink(new NormalLink(instr3, Link::SCOPE_EXTERNAL_JUMP));
      jbe9->setSemantic(jbeSem);

      mutator.insertBefore(insertpoint, instr1);
      mutator.insertBefore(insertpoint, jmp2);
      mutator.insertBefore(insertpoint, instr3);
      mutator.insertBefore(insertpoint, instr4);
      mutator.insertBefore(insertpoint, instr5);
      mutator.insertBefore(insertpoint, instr6);
      mutator.insertBefore(insertpoint, instr7);
      mutator.insertBefore(insertpoint, instr8);
      mutator.insertBefore(insertpoint, jbe9);
    }
    recurse(block);
}

void ReversePatch::extendstack(Function *func, size_t extendSize) {
  // extend stack size of single function
  StackExtendPass extender(extendSize);
  func->accept(&extender);
}
