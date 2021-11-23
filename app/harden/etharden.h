#ifndef EGALITO_APP_HARDEN_H
#define EGALITO_APP_HARDEN_H

#include "conductor/interface.h"

class HardenApp {
private:
    bool quiet;
    EgalitoInterface *egalito;
    // for revpatch
    Module *comparedModule;
    std::string funcname;
public:
    HardenApp() : quiet(true), comparedModule(nullptr) {}
    void run(int argc, char **argv);
    void parse(const std::string &filename, bool oneToOne);
    void revparse(const std::string &filename1, const std::string &filename2, bool oneToOne);
    void generate(const std::string &filename, bool oneToOne);
    Program *getProgram() const { return egalito->getProgram(); }
private:
    void doCFI();
    void doShadowStack(bool gsMode);
    void doPermuteData();
    void doProfiling();
    void doWatching();
    void doRetpolines();
    void doRevpatch();
};

#endif
