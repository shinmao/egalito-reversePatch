#include <iostream>
#include <functional>
#include <string>
#include <cstring>  // for std::strcmp
#include "etharden.h"
#include "pass/chunkpass.h"
#include "pass/stackxor.h"
#include "pass/endbradd.h"
#include "pass/endbrenforce.h"
#include "pass/shadowstack.h"
#include "pass/permutedata.h"
#include "pass/profileinstrument.h"
#include "pass/profilesave.h"
#include "pass/condwatchpoint.h"
#include "pass/retpoline.h"
#include "pass/reversepatch.h"
#include "log/registry.h"
#include "log/temp.h"

void HardenApp::parse(const std::string &filename, bool oneToOne) {
    egalito = new EgalitoInterface(!quiet, true);

    std::cout << "Transforming file [" << filename << "]\n";

    try {
        egalito->initializeParsing();

        if(oneToOne) {
            std::cout << "Parsing ELF file...\n";
        }
        else {
            std::cout << "Parsing ELF file and all shared library dependencies...\n";
        }
        egalito->parse(filename, !oneToOne);
    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
    }
}

void HardenApp::revparse(const std::string &filename1, const std::string &filename2, bool oneToOne) {
    egalito = new EgalitoInterface(!quiet, true);

    std::cout << "Tansforming two files [" << filename1 << ", " << filename2 << "] on " << funcname << "()\n";

    try {
        egalito->initializeParsing();

        if(oneToOne) {
            std::cout << "Parsing two ELF files...\n";
        }
        else {
            std::cout << "Parsing two ELF files with all shared library dependencies...\n";
        }
        egalito->parse(filename1, !oneToOne);
        comparedModule = egalito->parse(filename2, Library::ROLE_EXTRA, true);
    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
    }
}

void HardenApp::generate(const std::string &output, bool oneToOne) {
    std::cout << "Performing code generation into [" << output << "]...\n";
    egalito->generate(output, !oneToOne);
}

void HardenApp::doCFI() {
    auto program = getProgram();
    std::cout << "Adding endbr CFI...\n";
    EndbrAddPass endbradd;
    program->accept(&endbradd);

    EndbrEnforcePass endbrEnforce;
    program->accept(&endbrEnforce);
}

void HardenApp::doShadowStack(bool gsMode) {
    //egalito->getSetup()->addExtraLibraries(std::vector<std::string>{"libcet.so"});
    egalito->parse("libcet.so");
    auto program = getProgram();

    std::cout << "Adding shadow stack...\n";
    ShadowStackPass shadowStack(gsMode
        ? ShadowStackPass::MODE_GS : ShadowStackPass::MODE_CONST);
    program->accept(&shadowStack);
}

void HardenApp::doPermuteData() {
    std::cout << "Permuting data section...\n";
    auto program = getProgram();
    RUN_PASS(PermuteDataPass(), program);
}

void HardenApp::doProfiling() {
    std::cout << "Adding function profiling...\n";
    auto program = getProgram();
    RUN_PASS(ProfileInstrumentPass(), program);
    RUN_PASS(ProfileSavePass(), program);
}

void HardenApp::doWatching() {
    std::cout << "Adding conditional watchpoint...\n";
    auto program = getProgram();
    RUN_PASS(CondWatchpointPass(), program);
    //RUN_PASS(ProfileSavePass(), program);
}

void HardenApp::doRetpolines() {
    std::cout << "Adding retpolines...\n";
    auto program = getProgram();
    for(auto module : CIter::children(program)) {
        RUN_PASS(RetpolinePass(), module);
    }
}

void HardenApp::doRevpatch() {
    std::cout << "Comparing two modules on function: " << funcname << "\n";
    auto program = getProgram();
    auto module = program->getMain();
    ReversePatch revpatch(comparedModule, funcname);
    module->accept(&revpatch);
    //RUN_PASS(ReversePatch(), getProgram());
}

static void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [options] [mode] input-file output-file\n"
        "    Transforms an executable by adding CFI and a shadow stack.\n"
        "\n"
        "Options:\n"
        "    -v     Verbose mode, print logging messages\n"
        "    -q     Quiet mode (default), suppress logging messages\n"
        "    -m     Perform mirror elf generation (1-1 output)\n"
        "    -u     Perform union elf generation (merged output)\n"
        "\n"
        "Modes:\n"
        "    --nop          No transformation (default)\n"
        "    --retpolines   Add inline retpolines, SPECTRE mitigation\n"
        "    --cfi          Intel CET endbr-based Control-Flow Integrity\n"
        "    --ss           default shadow stack\n"
        "        --ss-xor        XOR-based shadowstack\n"
        "        --ss-gs         GS-Shadowstack with no endbr\n"
        "        --ss-const      Constant offset shadowstack\n"
        "    --cet          default Control-Flow Enforcement (Intel CET)\n"
        "        --cet-gs        GS shadow stack implementation\n"
        "        --cet-const     Constant offset shadow stack implementation\n"
        "    --permute-data Randomize order of global variables in .data\n"
        "    --profile      Add profiling counters to each function\n"
        "    --cond-watchpoint   Add conditional watchpoints for GDB\n"
        "    --rev-patch    [Extended] Generate patch on another version\n"
        "Note: the EGALITO_DEBUG variable is also honoured.\n";
}

void HardenApp::run(int argc, char **argv) {
    bool oneToOne = true;
    std::vector<std::string> ops;

    const struct {
        const char *str;
        std::function<void ()> action;
    } actions[] = {
        // should we show debugging log messages?
        {"-v", [this] () { quiet = false; }},
        {"-q", [this] () { quiet = true; }},

        // which elf gen should we perform?
        {"-m", [&oneToOne] () { oneToOne = true; }},
        {"-u", [&oneToOne] () { oneToOne = false; }},

        {"--nop",           [&ops] () { }},
        {"--retpolines",    [&ops] () { ops.push_back("retpolines"); }},
        {"--cfi",           [&ops] () { ops.push_back("cfi"); }},
        {"--ss",            [&ops] () { ops.push_back("ss-const"); }},
        {"--ss-xor",        [&ops] () { ops.push_back("ss-xor"); }},
        {"--ss-gs",         [&ops] () { ops.push_back("ss-gs"); }},
        {"--ss-const",      [&ops] () { ops.push_back("ss-const"); }},
        {"--cet",           [&ops] () { ops.push_back("cet-const"); }},
        {"--cet-gs",        [&ops] () { ops.push_back("cet-gs"); }},
        {"--cet-const",     [&ops] () { ops.push_back("cet-const"); }},
        {"--permute-data",  [&ops] () { ops.push_back("permute-data"); }},
        {"--profile",       [&ops] () { ops.push_back("profile"); }},
        {"--cond-watchpoint", [&ops] () { ops.push_back("cond-watchpoint"); }},
        {"--rev-patch",     [&ops] () {ops.push_back("reverse-patch"); }},
    };

    std::map<std::string, std::function<void ()>> techniques = {
        {"cfi",             [this] () { doCFI(); }},
        {"ss-xor",          [this] () { RUN_PASS(StackXOR(0x28), getProgram()); }},
        {"ss-gs",           [this] () { doShadowStack(true); }},
        {"ss-const",        [this] () { doShadowStack(false); }},
        {"cet-gs",          [this] () { doShadowStack(true); doCFI(); }},
        {"cet-const",       [this] () { doShadowStack(false); doCFI(); }},
        {"permute-data",    [this] () { doPermuteData(); }},
        {"profile",         [this] () { doProfiling(); }},
        {"cond-watchpoint", [this] () { doWatching(); }},
        {"retpolines",      [this] () { doRetpolines(); }},
        {"reverse-patch",   [this] () { doRevpatch(); }},
    };

    for(int a = 1; a < argc; a ++) {
        const char *arg = argv[a];
        if(arg[0] == '-') {
            bool found = false;
            for(auto action : actions) {
                if(std::strcmp(arg, action.str) == 0) {
                    action.action();
                    found = true;
                    break;
                }
            }
            if(!found) {
                std::cout << "Warning: unrecognized option \"" << arg << "\"\n";
            }
        }
        else if(argv[a] && argv[a + 1] && argv[a + 2]) {
            // case for rev ReversePatch
            // parse two binary and map to memory at the same time
	    funcname = argv[a + 2];
            revparse(argv[a], argv[a + 1], oneToOne);
            for(auto op : ops) {
              techniques[op]();
            }
            // no generation of elf
            break;
        }
        else if(argv[a] && argv[a + 1]) {
            parse(argv[a], oneToOne);
            for(auto op : ops) {
                techniques[op]();
            }
            generate(argv[a + 1], oneToOne);
            break;
        }
        else {
            std::cout << "Error: no output filename given!\n";
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printUsage(argv[0] ? argv[0] : "etharden");
        return 0;
    }

    HardenApp app;
    app.run(argc, argv);
    return 0;
}
