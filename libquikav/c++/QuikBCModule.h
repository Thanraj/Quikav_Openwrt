#include "llvm/Support/raw_ostream.h"
namespace llvm {
    class Function;
    class Instruction;
    class Pass;
}
namespace QuikBCModule {
    void stop(const char *msg, llvm::Function* F, llvm::Instruction* I=0);
}
llvm::Pass *createQuikBCRTChecks();
