#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <functional>
#include "parser.h"
#include "entry.h"
#include "state.h"
#include "platform.h"
#include "elf/elfmap.h"
#include "log/log.h"

DwarfParser::DwarfParser(ElfMap *elfMap) : info(nullptr),
    rememberedState(nullptr) {

    ElfSection *section = elfMap->findSection(".eh_frame");

    if(section) {
        this->readAddress = section->getReadAddress();
        this->virtualAddress = section->getVirtualAddress();
        parse(section->getSize());
    }
    else {
        LOG(0, "WARNING: no .eh_frame section present in ELF file!");
    }
}

void DwarfParser::parse(size_t virtualSize) {
    info = new DwarfUnwindInfo();
    DwarfCursor start(readAddress);
    DwarfCursor end(readAddress + virtualSize);

    LOG(10, "Contents of the .eh_frame section:");

    while(start < end) {
        uint64_t length = start.next<uint32_t>();
        uint64_t entryLength = length + 4;
        if(length == 0xfffffffful) {
            // the length is in the next 8 bytes
            start >> length;
            entryLength = length + 8;
        }

        if(length == 0) {
            CLOG(10, "\n%08lx ZERO terminator\n\n",
                start.getStart() - readAddress);
            break;
        }

        DwarfCursor startOfEntry{start.getCursor()};
        DwarfCursor endOfEntry{start.getStart() + entryLength};
        uint32_t entryID = start.next<uint32_t>();

        if(entryID == 0) {  // it's a CIE
            const uint64_t cieIndex = info->getCIECount();
            DwarfCIE *cie = parseCIE(start, endOfEntry, length, cieIndex);
            info->addCIE(cie);
        }
        else {  // it's an FDE within the given CIE
            uint64_t cieIndex;
            if(info->findCIE(startOfEntry.getCursor() - entryID, &cieIndex)) {
                DwarfFDE *fde = parseFDE(start, endOfEntry, length, cieIndex,
                    entryID);
                info->addFDE(fde);
            }
            else {
                LOG(1, "WARNING: unknown CIE index in FDE definition");
            }
        }

        start = endOfEntry;
    }
}

class DwarfExpressionDecoder {
private:
    DwarfCursor start;
    DwarfState *state;
    std::vector<uint64_t> evalStack;
public:
    DwarfExpressionDecoder(const DwarfCursor &start, DwarfState *state)
        : start(start), state(state) {}
    uint64_t decode();
private:
    template <typename Type>
    Type pop();

    template <typename Type>
    void push(Type value) { evalStack.push_back(value); }
private:
    template <typename Type>
    void decodeConstant(int bytes, char sign);

    template <typename Type>
    void decodeBinaryOp(const char *name,
        std::function<Type (Type, Type)> func);
};

#define OPCODE_CLOG(format, ...) \
    CLOG(11, format, __VA_ARGS__)
#define OPCODE_LOG(data) \
    LOG(11, data)
#define OPCODE_LOG0(data) \
    LOG0(11, data)
using std::printf;  // hack for now
using std::exit;  // hack for now

static uint64_t dereferencePointer(uint64_t pointer) {
    return *(reinterpret_cast<uint64_t *>(pointer));
}

template <typename Type>
Type DwarfExpressionDecoder::pop() {
    Type value = evalStack.back();
    evalStack.pop_back();
    return value;
}

template <typename Type>
void DwarfExpressionDecoder::decodeConstant(int bytes, char sign) {
    Type value = start.next<Type>();
    push(value);
    if(bytes == 8) {
        LOG0(11, "DW_OP_const8" << sign << ": "
            << (value & 0xFFFFFFFF00000000) << " "
            << (value & 0x00000000FFFFFFFF));
    }
    else {
        LOG0(11, "DW_OP_const" << bytes << sign << ": " << value);
    }
}

template <typename Type>
void DwarfExpressionDecoder::decodeBinaryOp(const char *name,
    std::function<Type (Type, Type)> func) {

    Type value = pop<Type>();
    evalStack.back() = func(static_cast<Type>(evalStack.back()), value);
    LOG0(11, "DP_OP_" << name);
}

uint64_t DwarfExpressionDecoder::decode() {
    uint64_t length = start.nextUleb128();
    DwarfCursor end = start;
    end.skip(length);
    evalStack.reserve(100);

    while(start < end) {
        uint8_t opcode = start.next<uint8_t>();
        int64_t svalue;
        uint64_t value;
        uint64_t reg;
        switch (opcode) {
        case DW_OP_addr:
            start >> value;
            printf("DW_OP_addr: %lx", value);
            push(value);
            break;

        case DW_OP_deref:
            value = pop<uint64_t>();
            push(dereferencePointer(value));
            printf ("DW_OP_deref");
            break;
        case DW_OP_xderef:
            value = pop<uint64_t>();
            push(dereferencePointer(value));
            printf ("DW_OP_xderef");
            break;

        case DW_OP_const1u: decodeConstant<uint8_t>(1, 'u'); break;
        case DW_OP_const1s: decodeConstant<int8_t>(1, 's'); break;
        case DW_OP_const2u: decodeConstant<uint16_t>(2, 'u'); break;
        case DW_OP_const2s: decodeConstant<int16_t>(2, 's'); break;
        case DW_OP_const4u: decodeConstant<uint32_t>(4, 'u'); break;
        case DW_OP_const4s: decodeConstant<int32_t>(4, 's'); break;
        case DW_OP_const8u: decodeConstant<uint64_t>(8, 'u'); break;
        case DW_OP_const8s: decodeConstant<int64_t>(8, 's'); break;
        case DW_OP_constu: {
            uint64_t value = start.nextUleb128();
            push(value);
            LOG0(11, "DW_OP_constu: " << value);
            break;
        }
        case DW_OP_consts: {
            int64_t svalue = start.nextSleb128();
            push(svalue);
            LOG0(11, "DW_OP_consts: " << value);
            break;
        }

        case DW_OP_dup:
            value = evalStack.back();
            push(value);
            printf ("DW_OP_dup");
            break;
        case DW_OP_drop:
            pop<uint64_t>();
            printf ("DW_OP_drop");
            break;
        case DW_OP_over:
            value = evalStack[evalStack.size() - 2];
            evalStack.push_back(value);
            printf ("DW_OP_over");
            break;
        case DW_OP_pick:
            reg = start.next<uint8_t>();
            value = evalStack[evalStack.size() - 1 - reg];
            push(value);
            printf ("DW_OP_pick: %ld", (uint64_t)reg);
            break;
        case DW_OP_swap:
            value = evalStack[evalStack.size() - 1];
            evalStack[evalStack.size() - 1] = evalStack[evalStack.size() - 2];
            evalStack[evalStack.size() - 2] = value;
            printf ("DW_OP_swap");
            break;
        case DW_OP_rot:
            value = evalStack[evalStack.size() - 1];
            evalStack[evalStack.size() - 1] = evalStack[evalStack.size() - 2];
            evalStack[evalStack.size() - 2] = evalStack[evalStack.size() - 3];
            evalStack[evalStack.size() - 3] = value;
            printf ("DW_OP_rot");
            break;

        case DW_OP_abs:
            svalue = evalStack.back();
            if(svalue < 0) {
                evalStack.back() = -svalue;
            }
            printf ("DW_OP_abs");
            break;
        case DW_OP_neg:
            evalStack.back() = -evalStack.back();
            printf ("DW_OP_neg");
            break;
        case DW_OP_not:
            evalStack.back() = ~evalStack.back();
            printf ("DW_OP_not");
            break;

        case DW_OP_and:
            value = pop<uint64_t>();
            evalStack.back() &= value;
            printf ("DW_OP_and");
            break;
        case DW_OP_or:
            value = pop<uint64_t>();
            evalStack.back() |= value;
            printf ("DW_OP_or");
            break;
        case DW_OP_xor:
            value = pop<uint64_t>();
            evalStack.back() ^= value;
            printf ("DW_OP_xor");
            break;
        case DW_OP_div:
            svalue = pop<int64_t>();
            evalStack.back() = evalStack.back() / svalue;
            printf ("DW_OP_div");
            break;
        case DW_OP_minus:
            svalue = pop<int64_t>();
            evalStack.back() = evalStack.back() - svalue;
            printf ("DW_OP_minus");
            break;
        case DW_OP_mod:
            svalue = pop<int64_t>();
            evalStack.back() = evalStack.back() % svalue;
            printf ("DW_OP_mod");
            break;
        case DW_OP_mul:
            svalue = pop<int64_t>();
            evalStack.back() = evalStack.back() * svalue;
            printf ("DW_OP_mul");
            break;

        case DW_OP_plus:  // !!! shouldn't this be signed?
            value = pop<uint64_t>();
            evalStack.back() += value;
            printf ("DW_OP_plus");
            break;
        case DW_OP_plus_uconst:
            // pop stack, add uelb128 constant, push result
            value = start.nextUleb128();
            evalStack.back() += value;
            printf ("DW_OP_plus_uconst: %lu", value);
            break;

        case DW_OP_shl:
            value = pop<uint64_t>();
            evalStack.back() = evalStack.back() << value;
            printf ("DW_OP_shl");
            break;
        case DW_OP_shr:
            value = pop<uint64_t>();
            evalStack.back() = evalStack.back() >> value;
            printf ("DW_OP_shr");
            break;
        case DW_OP_shra:
            value = pop<uint64_t>();
            svalue = evalStack.back();
            evalStack.back() = svalue >> value;
            printf ("DW_OP_shra");
            break;

        case DW_OP_skip:
            svalue = start.next<int16_t>();
            start.skip(svalue);
            printf ("DW_OP_skip: %ld", svalue);
            break;
        case DW_OP_bra:
            svalue = start.next<int16_t>();
            if(evalStack.size() > 0) {
                evalStack.pop_back();
                start.skip(svalue);
            }
            printf ("DW_OP_bra: %ld", svalue);
            break;

        case DW_OP_eq:
            value = pop<uint64_t>();
            evalStack.back() = (evalStack.back() == value);
            printf ("DW_OP_eq");
            break;
        case DW_OP_ge:
            value = pop<uint64_t>();
            evalStack.back() = (evalStack.back() >= value);
            printf ("DW_OP_ge");
            break;
        case DW_OP_gt:
            value = pop<uint64_t>();
            evalStack.back() = (evalStack.back() > value);
            printf ("DW_OP_gt");
            break;
        case DW_OP_le:
            value = pop<uint64_t>();
            evalStack.back() = (evalStack.back() <= value);
            printf ("DW_OP_le");
            break;
        case DW_OP_lt:
            value = pop<uint64_t>();
            evalStack.back() = (evalStack.back() < value);
            printf ("DW_OP_lt");
            break;
        case DW_OP_ne:
            value = pop<uint64_t>();
            evalStack.back() = (evalStack.back() != value);
            printf ("DW_OP_ne");
            break;

        case DW_OP_lit0: case DW_OP_lit1: case DW_OP_lit2: case DW_OP_lit3:
        case DW_OP_lit4: case DW_OP_lit5: case DW_OP_lit6: case DW_OP_lit7:
        case DW_OP_lit8: case DW_OP_lit9: case DW_OP_lit10: case DW_OP_lit11:
        case DW_OP_lit12: case DW_OP_lit13: case DW_OP_lit14: case DW_OP_lit15:
        case DW_OP_lit16: case DW_OP_lit17: case DW_OP_lit18: case DW_OP_lit19:
        case DW_OP_lit20: case DW_OP_lit21: case DW_OP_lit22: case DW_OP_lit23:
        case DW_OP_lit24: case DW_OP_lit25: case DW_OP_lit26: case DW_OP_lit27:
        case DW_OP_lit28: case DW_OP_lit29: case DW_OP_lit30: case DW_OP_lit31:
            value = opcode - DW_OP_lit0;
            push(value);
            printf ("DW_OP_lit%ld", value);
            break;

        case DW_OP_reg0: case DW_OP_reg1: case DW_OP_reg2: case DW_OP_reg3:
        case DW_OP_reg4: case DW_OP_reg5: case DW_OP_reg6: case DW_OP_reg7:
        case DW_OP_reg8: case DW_OP_reg9: case DW_OP_reg10: case DW_OP_reg11:
        case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14: case DW_OP_reg15:
        case DW_OP_reg16: case DW_OP_reg17: case DW_OP_reg18: case DW_OP_reg19:
        case DW_OP_reg20: case DW_OP_reg21: case DW_OP_reg22: case DW_OP_reg23:
        case DW_OP_reg24: case DW_OP_reg25: case DW_OP_reg26: case DW_OP_reg27:
        case DW_OP_reg28: case DW_OP_reg29: case DW_OP_reg30: case DW_OP_reg31:
            reg = opcode - DW_OP_reg0;
            //TODO: Not sure about the following operation
            //Using offsets for now, but might need to use values or
            //something else completely
            push(state->get(reg).getOffset());
            printf ("DW_OP_reg%ld", reg);
            break;

        case DW_OP_regx:
            reg = start.nextUleb128();
            //TODO: Not sure about the following operation
            //Using offsets for now, but might need to use values or
            //something else completely
            push(state->get(reg).getOffset());
            printf ("DW_OP_regx: %lu", reg);
            break;          

        case DW_OP_breg0: case DW_OP_breg1: case DW_OP_breg2: case DW_OP_breg3:
        case DW_OP_breg4: case DW_OP_breg5: case DW_OP_breg6: case DW_OP_breg7:
        case DW_OP_breg8: case DW_OP_breg9: case DW_OP_breg10: case DW_OP_breg11:
        case DW_OP_breg12: case DW_OP_breg13: case DW_OP_breg14: case DW_OP_breg15:
        case DW_OP_breg16: case DW_OP_breg17: case DW_OP_breg18: case DW_OP_breg19:
        case DW_OP_breg20: case DW_OP_breg21: case DW_OP_breg22: case DW_OP_breg23:
        case DW_OP_breg24: case DW_OP_breg25: case DW_OP_breg26: case DW_OP_breg27:
        case DW_OP_breg28: case DW_OP_breg29: case DW_OP_breg30: case DW_OP_breg31:
            reg = opcode - DW_OP_breg0;
            svalue = start.nextSleb128();
            //TODO: Not sure about the following operation
            //Using offsets for now, but might need to use values or
            //something else completely
            push(state->get(reg).getOffset() + svalue);
            printf ("DW_OP_breg%ld (%s): %ld", reg, shortRegisterName(reg), svalue);
            break;

        case DW_OP_bregx:
            reg = start.nextUleb128();
            svalue = start.nextSleb128();
            //TODO: Not sure about the following operation
            //Using offsets for now, but might need to use values or
            //something else completely
            push(state->get(reg).getOffset() + svalue);
            printf ("DW_OP_bregx: %lu %ld", reg, svalue);
            break;

        case DW_OP_deref_size:
            // pop stack, dereference, push result
            value = evalStack.back(); evalStack.pop_back();
            printf ("DW_OP_deref_size: %lu", value);
            switch (start.next<uint8_t>()) {
            case 1: value = start.next<uint8_t>(); break;
            case 2: value = start.next<uint16_t>(); break;
            case 4: value = start.next<uint32_t>(); break;
            case 8: value = start.next<uint64_t>(); break;
            default:
                //TODO:FATAL
                printf("Invalid size in DW_OP_deref_size");
                exit(1);
            }
            evalStack.push_back(value);
            break;

        case DW_OP_xderef_size:
        case DW_OP_nop:
        case DW_OP_push_object_address:
        case DW_OP_call2:
        case DW_OP_call4:
        case DW_OP_call_ref:
        case DW_OP_piece:
        case DW_OP_fbreg:
        default:
            //TODO:FATAL
            printf("DW_OP_* is not supported");
            exit(1);
        }
        if(start < end) {
            printf("; ");
        }
    }
    return evalStack.back();
}

DwarfState *DwarfParser::parseInstructions(DwarfCursor start, DwarfCursor end,
    DwarfCIE *cie, uint64_t cfaIp) {

    DwarfState *state = new DwarfState(*cie->getState());

    const uint64_t codeAlignFactor = cie->getCodeAlignFactor();
    const int64_t dataAlignFactor = cie->getDataAlignFactor();
    uint64_t ul, reg, registerOffset;
    int64_t l, ofs;
    uint64_t nextIp;

    while(start < end) {
        uint8_t opcode;
        start >> opcode;

        uint64_t op = opcode & 0x3f;

        if(opcode & 0xc0) {
            opcode &= 0xc0;
        }

        switch (opcode) {
        case DW_CFA_advance_loc:
            nextIp = cfaIp + op * codeAlignFactor; 
            printf("  DW_CFA_advance_loc: %ld to %016lx\n", op * codeAlignFactor, nextIp);
            cfaIp = nextIp;
            break;

        case DW_CFA_offset:
            registerOffset = start.nextUleb128();
            printf("  DW_CFA_offset: %s at cfa%+ld\n", getRegisterName(op).c_str(), registerOffset * dataAlignFactor);
            state->set(op, DW_CFA_offset, registerOffset * dataAlignFactor);
            break;

        case DW_CFA_restore:
            printf ("  DW_CFA_restore: %s\n", getRegisterName(op).c_str());
            state->set(op, cie->getState()->get(op));
            break;

        case DW_CFA_set_loc:
            if(cie->getAugmentation()) {
                cfaIp = start.nextEncodedPointer<int64_t>(
                    cie->getAugmentation()->getCodeEnc());
                printf ("  DW_CFA_set_loc: %08lx\n", cfaIp);
            }
            break;

        case DW_CFA_advance_loc1:
            ofs = start.next<uint8_t>();
            nextIp = cfaIp + ofs * codeAlignFactor;

            printf("  DW_CFA_advance_loc1: %ld to %016lx\n",
                    ofs * codeAlignFactor,
                    nextIp);
            cfaIp = nextIp;
            break;

        case DW_CFA_advance_loc2:
            ofs = start.next<uint16_t>();
            nextIp = cfaIp + ofs * codeAlignFactor;

            printf("  DW_CFA_advance_loc2: %ld to %016lx\n",
                    ofs * codeAlignFactor,
                    nextIp);
            cfaIp = nextIp;
            break;

        case DW_CFA_advance_loc4:
            ofs = start.next<uint32_t>();
            nextIp = cfaIp + ofs * codeAlignFactor;

            printf("  DW_CFA_advance_loc4: %ld to %016lx\n",
                    ofs * codeAlignFactor,
                    nextIp);
            cfaIp = nextIp;
            break;

        case DW_CFA_offset_extended:
            reg = start.nextUleb128();
            registerOffset = start.nextUleb128();
            printf("  DW_CFA_offset_extended: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    registerOffset * dataAlignFactor);
            state->set(reg, DW_CFA_offset, registerOffset * dataAlignFactor);
            break;

        case DW_CFA_val_offset:
            reg = start.nextUleb128();
            registerOffset = start.nextUleb128();
            printf("  DW_CFA_val_offset: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    registerOffset * dataAlignFactor);
            state->set(reg, DW_CFA_val_offset, registerOffset * dataAlignFactor);
            break;

        case DW_CFA_restore_extended:
            reg = start.nextUleb128();
            printf("  DW_CFA_restore_extended: %s\n",
                    getRegisterName(reg).c_str());
            state->set(reg, cie->getState()->get(reg));
            break;

        case DW_CFA_undefined:
            reg = start.nextUleb128();
            printf("  DW_CFA_undefined: %s\n",
                    getRegisterName(reg).c_str());
            state->set(reg, DW_CFA_undefined, 0);
            break;

        case DW_CFA_same_value:
            reg = start.nextUleb128();
            printf("  DW_CFA_same_value: %s\n",
                    getRegisterName(reg).c_str());
            state->set(reg, DW_CFA_same_value, 0);
            break;

        case DW_CFA_register:
            reg = start.nextUleb128();
            registerOffset = start.nextUleb128();
            printf("  DW_CFA_register: %s in %s\n",
                    getRegisterName(reg).c_str(), getRegisterName(registerOffset).c_str());
            state->set(reg, DW_CFA_register, registerOffset);
            break;

        case DW_CFA_remember_state: {
            printf("  DW_CFA_remember_state\n");
            auto tempState = new DwarfState(*state);
            tempState->setNext(rememberedState);
            rememberedState = tempState;
            break;
        }
        case DW_CFA_restore_state: {
            printf("  DW_CFA_restore_state\n");
            if(auto tempState = rememberedState) {
                rememberedState = tempState->getNext();
                *state = *tempState;  // copy data
                delete tempState;
            }
            break;
        }

        case DW_CFA_def_cfa:
            state->setCfaRegister(start.nextUleb128());
            state->setCfaOffset(start.nextUleb128());
            state->setCfaExpression(0);
            printf("  DW_CFA_def_cfa: %s ofs %ld\n",
                getRegisterName(state->getCfaRegister()).c_str(),
                state->getCfaOffset());
            break;

        case DW_CFA_def_cfa_register:
            state->setCfaRegister(start.nextUleb128());
            state->setCfaExpression(0);
            printf("  DW_CFA_def_cfa_register: %s\n",
                getRegisterName(state->getCfaRegister()).c_str());
            break;

        case DW_CFA_def_cfa_offset:
            state->setCfaOffset(start.nextUleb128());
            printf("  DW_CFA_def_cfa_offset: %ld\n", state->getCfaOffset());
            break;

        case DW_CFA_nop:
            printf("  DW_CFA_nop\n");
            break;

        case DW_CFA_def_cfa_expression:
            //TODO: Complete this decoding
            printf("  DW_CFA_def_cfa_expression (");
            DwarfExpressionDecoder(start, state).decode();
            printf(")\n");
            state->setCfaExpression(start.getCursor());
            ul = start.nextUleb128();
            start.skip(ul);
            break;

        case DW_CFA_expression:
            reg = start.nextUleb128();
            state->set(reg, DW_CFA_expression, start.getCursor());
            //TODO: Complete this decoding
            printf("  DW_CFA_expression: %s (",
                getRegisterName(reg).c_str());
            DwarfExpressionDecoder(start, state).decode();
            printf(")\n");
            ul = start.nextUleb128();
            start.skip(ul);
            break;

        case DW_CFA_val_expression:
            reg = start.nextUleb128();
            //TODO: Complete this decoding
            printf("  DW_CFA_val_expression: %s (",
                    getRegisterName(reg).c_str());
            DwarfExpressionDecoder(start, state).decode();
            printf (")\n");
            ul = start.nextUleb128();
            state->set(reg, DW_CFA_val_expression, state->get(reg).getOffset());
            start.skip(ul);
            break;

        case DW_CFA_offset_extended_sf:
            reg = start.nextUleb128();
            l = start.nextSleb128();
            printf("  DW_CFA_offset_extended_sf: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    l * dataAlignFactor);
            state->set(reg, DW_CFA_offset, l * dataAlignFactor);
            break;

        case DW_CFA_val_offset_sf:
            reg = start.nextUleb128();
            l = start.nextSleb128();
            printf("  DW_CFA_val_offset_sf: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    l * dataAlignFactor);
            state->set(reg, DW_CFA_val_offset, l * dataAlignFactor);
            break;

        case DW_CFA_def_cfa_sf:
            state->setCfaRegister(start.nextUleb128());
            state->setCfaOffset(start.nextSleb128() * dataAlignFactor);
            state->setCfaExpression(0);
            printf("  DW_CFA_def_cfa_sf: %s ofs %ld\n",
                getRegisterName(state->getCfaRegister()).c_str(),
                state->getCfaOffset());
            break;

        case DW_CFA_def_cfa_offset_sf:
            state->setCfaOffset(start.nextSleb128() * dataAlignFactor);
            printf("  DW_CFA_def_cfa_offset_sf: %ld\n", state->getCfaOffset());
            break;

        case DW_CFA_MIPS_advance_loc8:
            ofs = start.next<uint64_t>();
            printf("  DW_CFA_MIPS_advance_loc8: %ld to %016lx\n",
                    ofs * codeAlignFactor,
                    cfaIp + ofs * codeAlignFactor);
            cfaIp += ofs * codeAlignFactor;
            break;

        case DW_CFA_GNU_window_save:
            printf("  DW_CFA_GNU_window_save\n");
            break;

        case DW_CFA_GNU_args_size:
            ul = start.nextUleb128();
            printf("  DW_CFA_GNU_args_size: %ld\n", ul);
            break;

        case DW_CFA_GNU_negative_offset_extended:
            reg = start.nextUleb128();
            l = -start.nextUleb128();
            printf("  DW_CFA_GNU_negative_offset_extended: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    l * dataAlignFactor);
            state->set(reg, DW_CFA_offset, l * dataAlignFactor);
            break;

        default:
            printf("  DW_CFA_??? (User defined call frame opcode: %#x)\n", opcode);
            start = end;
        }
    }

    return state;
}

DwarfCIE *DwarfParser::parseCIE(DwarfCursor start, DwarfCursor end,
    uint64_t length, uint64_t index) {

    DwarfCIE *cie = new DwarfCIE(start.getStart(), length, index);

    uint8_t version = start.next<uint8_t>();
    if(version != 1 && version != 3) {
        LOG(1, "ERROR: Dwarf version number is not 1 or 3");
        return nullptr;
    }

    auto cieAugmentationString = start.nextString();
    cie->setCodeAlignFactor(start.nextUleb128());
    cie->setDataAlignFactor(start.nextSleb128());
    cie->setRetAddressReg(start.nextUleb128());

    if(*cieAugmentationString) {
        if(*cieAugmentationString != 'z') {
            LOG(1, "ERROR: Augmentation string should start with '\\0' or 'z'");
            return nullptr;
        }

        auto augmentation = new DwarfCIE::Augmentation();

        start.nextUleb128();  // skip the augmentation length
        for(uint8_t *ptr = cieAugmentationString + 1; *ptr; ptr ++) {
            switch(static_cast<char>(*ptr)) {
            case 'P':
                augmentation->setPersonalityEncoding(start.next<uint8_t>());
                augmentation->setPersonalityEncodingRoutine(
                    start.nextEncodedPointer<uint64_t>(augmentation->getPersonalityEncoding()));
                break;
            case 'R':
                augmentation->setCodeEnc(start.next<uint8_t>());
                break;
            case 'L':
                augmentation->setLsdaEnc(start.next<uint8_t>());
                break;
            case 'S':
                augmentation->setIsSignal(true);
                break;
            default:
                LOG(11, "Unknown DWARF LSDA encoding character '" << *ptr << "'");
                break;
            }
        }

        cie->setAugmentation(augmentation);
    }

    printf("\n%08lx %016lx %08lx CIE\n",
        start.getStart() - readAddress, length, 0ul);
    printf("  Version:               %d\n", version);
    printf("  Augmentation:          \"%s\"\n", cieAugmentationString);
    printf("  Code alignment factor: %lu\n", cie->getCodeAlignFactor());
    printf("  Data alignment factor: %ld\n", cie->getDataAlignFactor());
    printf("  Return address column: %lu\n", cie->getRetAddressReg());
    printf("\n");

    auto state = parseInstructions(start, end, cie, 0);
    cie->setState(state);
    return cie;
}

DwarfFDE *DwarfParser::parseFDE(DwarfCursor start, DwarfCursor end,
    uint64_t length, uint64_t cieIndex, uint32_t entryID) {

    DwarfCIE *cie = info->getCIE(cieIndex);
    DwarfFDE *fde = new DwarfFDE(start.getStart(), length, cieIndex);
    fde->setCiePointer(entryID);

    uint8_t codeEnc = cie->getAugmentation()
        ? cie->getAugmentation()->getCodeEnc() : 0;

    fde->setPcBegin(start.nextEncodedPointer<int64_t>(codeEnc) + virtualAddress);
    fde->setPcRange(start.nextEncodedPointer<uint64_t>(codeEnc & 0x0f));

    if(cie->getAugmentation()) {  // if CIE has augmentation, so do FDEs
        start.nextUleb128();  // skip the augmentation length

        // will be set to 0 if the LSDA encoding is DW_EH_PE_omit
        const auto lsdaPointer = start.nextEncodedPointer<uint64_t>(
            cie->getAugmentation()->getLsdaEnc());

        fde->setAugmentation(new DwarfFDE::Augmentation(lsdaPointer));
    }

    printf("\n%08lx %016lx %08lx FDE cie=%08lx pc=%016lx..%016lx\n",
        start.getStart() - readAddress, length,
        static_cast<uint64_t>(fde->getCiePointer()),
        cie->getStartAddress() - readAddress,
        fde->getPcBegin() - readAddress, 
        fde->getPcBegin() - readAddress + fde->getPcRange());
    auto state = parseInstructions(start, end, cie, fde->getPcBegin() - readAddress);
    fde->setState(state);
    return fde;
}