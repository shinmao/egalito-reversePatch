#ifndef EGALITO_CHUNK_FUNCTION_H
#define EGALITO_CHUNK_FUNCTION_H

#include "chunk.h"
#include "chunklist.h"
#include "block.h"
#include "archive/chunktypes.h"

class Symbol;
class Function;
class ChunkCache;

class Function : public ChunkSerializerImpl<TYPE_Function,
    CompositeChunkImpl<Block>> {
private:
    Symbol *symbol;
    std::string name;
    bool nonreturn;
    ChunkCache *cache;
public:
    Function() : symbol(nullptr), nonreturn(false), cache(nullptr) {}

    /** Create a fuzzy function named according to the original address. */
    Function(address_t originalAddress);

    /** Create an authoritative function from symbol information. */
    Function(Symbol *symbol);

    Symbol *getSymbol() const { return symbol; }
    virtual std::string getName() const { return name; }
    virtual void setName(const std::string &name) { this->name = name; }

    /** Check if the given name is a valid alias for this function. */
    virtual bool hasName(std::string name) const;

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);

    bool returns() const { return !nonreturn; }
    void setNonreturn() { nonreturn = true; }

    void makeCache();
    ChunkCache *getCache() const { return cache; }
};

class FunctionList : public ChunkSerializerImpl<TYPE_FunctionList,
    CollectionChunkImpl<Function>> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor);

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);
};

#endif
