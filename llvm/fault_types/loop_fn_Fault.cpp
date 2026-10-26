#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>

#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/GlobalDCE.h"
#include "llvm/Transforms/IPO/GlobalOpt.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar/ADCE.h"
#include "llvm/Transforms/Scalar/CorrelatedValuePropagation.h"
#include "llvm/Transforms/Scalar/DCE.h"
#include "llvm/Transforms/Scalar/IndVarSimplify.h"
#include "llvm/Transforms/Scalar/LoopRotation.h"
#include "llvm/Transforms/Scalar/LoopUnrollPass.h"
#include "llvm/Transforms/Scalar/SCCP.h"
#include "llvm/Transforms/Scalar/SimplifyCFG.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"

#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Casting.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>

#include <llvm-20/llvm/IR/Intrinsics.h>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

using namespace llvm;
static constexpr unsigned kMaxUnrollTripCount = 2000;

enum FaultMode { LOOP_SKIP = 0, FUNC_SKIP = 1 };
static Instruction *getInstByIndex(Function &F, unsigned targetInst) {
  unsigned idx = 0;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (idx == targetInst)
        return &I;
      ++idx;
    }
  }
  return nullptr;
}

struct InstLocator {
  bool hasDbg = false;
  unsigned dbgLine = 0;
  unsigned dbgCol = 0;
  unsigned fallbackIndex = 0;
};

static InstLocator captureInstLocator(Instruction *I, unsigned idxInFunction) {
  InstLocator loc;
  loc.fallbackIndex = idxInFunction;
  if (DebugLoc DL = I->getDebugLoc()) {
    loc.hasDbg = true;
    loc.dbgLine = DL.getLine();
    loc.dbgCol = DL.getCol();
  }
  return loc;
}

static bool locMatches(Instruction *I, const InstLocator &loc) {
  if (!loc.hasDbg)
    return false;
  DebugLoc DL = I->getDebugLoc();
  return DL && DL.getLine() == loc.dbgLine && DL.getCol() == loc.dbgCol;
}

static Instruction *findInstByLocator(Function &F, const InstLocator &loc) {
  if (loc.hasDbg) {
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (locMatches(&I, loc))
          return &I;
    return nullptr;
  }
  return getInstByIndex(F, loc.fallbackIndex);
}
class FuncSkip : public PassInfoMixin<FuncSkip> {
private:
  InstLocator loc;
  std::string targetFuncName;

public:
  FuncSkip(InstLocator loc, std::string targetFuncName)
      : loc(loc), targetFuncName(std::move(targetFuncName)) {}
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
    if (F.getName() != targetFuncName)
      return PreservedAnalyses::all();

    auto &LI = FAM.getResult<LoopAnalysis>(F);
    auto &SE = FAM.getResult<ScalarEvolutionAnalysis>(F);

    std::vector<Loop *> loops(LI.begin(), LI.end());
    for (Loop *L : loops) {
      unsigned tripCount = SE.getSmallConstantTripCount(L);
      if (tripCount == 0) {
        errs() << "cannot determine trip count\n";
        continue;
      }
      if (tripCount > kMaxUnrollTripCount) {
        errs() << "Loop trip count " << tripCount << " exceeds max ("
               << kMaxUnrollTripCount << "); skipping unroll for this loop\n";
        continue;
      }
      errs() << "Loop trip count: " << tripCount << "\n";
      addLabelNUnrollWithFuncSkip(F, L, LI, SE, tripCount);
    }
    return PreservedAnalyses::none();
  }

  void addLabelNUnrollWithFuncSkip(Function &F, Loop *L, LoopInfo &LI,
                                   ScalarEvolution &SE, unsigned tripCount) {
    BasicBlock *header = L->getHeader();
    BasicBlock *latch = L->getLoopLatch();
    BasicBlock *preheader = L->getLoopPreheader();
    BasicBlock *exitBB = L->getUniqueExitBlock();

    if (!header || !latch || !preheader || !exitBB) {
      errs() << "Loop not in simplified form\n";
      return;
    }

    std::vector<BasicBlock *> origBlocks;
    for (BasicBlock *BB : L->blocks()) {
      origBlocks.push_back(BB);
    }

    BasicBlock *prevIterExit = preheader;
    ValueToValueMapTy cumulativeMap;

    for (unsigned i = 0; i < tripCount; i++) {
      // 1. Create start label
      BasicBlock *iterStart = BasicBlock::Create(
          F.getContext(), "iter_" + std::to_string(i) + "_start", &F);

      // 2. Resolve PHI nodes for this iteration
      std::vector<std::pair<PHINode *, Value *>> resolvedPhis;
      for (PHINode &PN : header->phis()) {
        Value *incoming;
        if (i == 0) {
          incoming = PN.getIncomingValueForBlock(preheader);
        } else {
          Value *latchVal = PN.getIncomingValueForBlock(latch);
          if (Value *mapped = cumulativeMap.lookup(latchVal))
            incoming = mapped;
          else
            incoming = latchVal;
        }
        cumulativeMap[&PN] = incoming;
        resolvedPhis.push_back({&PN, incoming});
      }

      // 3. Clone all blocks for this iteration
      std::vector<BasicBlock *> iterationCloned;
      ValueToValueMapTy iterationBlockMap;
      for (BasicBlock *BB : origBlocks) {
        BasicBlock *cloned =
            CloneBasicBlock(BB, cumulativeMap, ".iter" + std::to_string(i), &F);
        iterationCloned.push_back(cloned);
        iterationBlockMap[BB] = cloned;

        // Map individual instructions to their clones
        auto itOrig = BB->begin();
        auto itCloned = cloned->begin();
        while (itOrig != BB->end() && itCloned != cloned->end()) {
          iterationBlockMap[&*itOrig] = &*itCloned;
          // For next iteration's use
          cumulativeMap[&*itOrig] = &*itCloned;
          itOrig++;
          itCloned++;
        }
      }

      // 4. Resolve internal control flow in the cloned iteration
      for (BasicBlock *cloned : iterationCloned) {
        for (Instruction &I : *cloned) {
          RemapInstruction(&I, iterationBlockMap,
                           RF_NoModuleLevelChanges | RF_IgnoreMissingLocals);
        }

        // Skip function calls in the first iteration
        if (i == 0) {
          for (auto It = cloned->begin(); It != cloned->end();) {
            Instruction *I = &*It++;
            auto *CI = dyn_cast<CallInst>(I);
            if (!CI)
              continue;

            if (locMatches(CI, loc)) {
              outs() << "skipping fn call "
                     << (CI->getCalledFunction()
                             ? CI->getCalledFunction()->getName()
                             : "<indirect>")
                     << " at dbg " << loc.dbgLine << ":" << loc.dbgCol << "\n";
              if (!CI->getType()->isVoidTy() && CI->arg_size() > 0) {
                Value *v = CI->getArgOperand(0);
                CI->replaceAllUsesWith(v);
              }
              CI->eraseFromParent();
            }
          }
        }
      }

      // 5. Remove PHI nodes from the cloned header as they are now resolved
      for (auto &pair : resolvedPhis) {
        PHINode *origPhi = pair.first;
        Value *resolvedVal = pair.second;
        if (Value *clonedPhiVal = iterationBlockMap.lookup(origPhi)) {
          PHINode *clonedPhi = cast<PHINode>(clonedPhiVal);
          clonedPhi->replaceAllUsesWith(resolvedVal);
          clonedPhi->eraseFromParent();
        }
      }

      // 6. Create end label
      BasicBlock *iterEnd = BasicBlock::Create(
          F.getContext(), "iter_" + std::to_string(i) + "_end", &F);

      // 7. Connect control flow
      if (i == 0) {
        Instruction *prevTerm = preheader->getTerminator();
        BranchInst::Create(iterStart, preheader);
        prevTerm->eraseFromParent();
      } else {
        BranchInst::Create(iterStart, prevIterExit);
      }

      BranchInst::Create(iterationCloned.front(), iterStart);

      BasicBlock *clonedLatch = cast<BasicBlock>(iterationBlockMap[latch]);
      Instruction *latchTerm = clonedLatch->getTerminator();
      BranchInst::Create(iterEnd, clonedLatch);
      latchTerm->eraseFromParent();

      prevIterExit = iterEnd;
    }

    BranchInst::Create(exitBB, prevIterExit);
    for (auto it = exitBB->begin(); isa<PHINode>(it);) {
      PHINode *PN = cast<PHINode>(&*it++);
      Value *incomingVal = nullptr;

      for (unsigned j = 0; j < PN->getNumIncomingValues(); j++) {
        if (L->contains(PN->getIncomingBlock(j))) {
          incomingVal = PN->getIncomingValue(j);
          break;
        }
      }

      if (!incomingVal)
        continue;

      if (Value *mapped = cumulativeMap.lookup(incomingVal))
        incomingVal = mapped;

      while (true) {
        bool removed = false;
        for (unsigned j = 0; j < PN->getNumIncomingValues(); j++) {
          if (L->contains(PN->getIncomingBlock(j))) {
            PN->removeIncomingValue(j, false);
            removed = true;
            break;
          }
        }
        if (!removed)
          break;
      }

      PN->addIncoming(incomingVal, prevIterExit);
    }
    for (BasicBlock *BB : origBlocks) {
      BB->eraseFromParent();
    }
    // NOTE: Do NOT manually erase origBlocks here.
    // The original loop blocks are now unreachable and will be safely removed
    // by subsequent DCE passes (GlobalDCEPass, ADCEPass, DCEPass).
    // Manually erasing them causes memory corruption because LLVM's internal
    // data structures (like LoopInfo) still reference these blocks.
  }
};

void dump_module(llvm::Module &M, const std::string &filename) {
  // Create parent directories.
  SmallString<256> path(filename);
  sys::path::remove_filename(path);

  if (!path.empty()) {
    if (std::error_code EC = llvm::sys::fs::create_directories(path)) {
      llvm::errs() << "Failed to create directories: " << EC.message() << "\n";
      return;
    }
  }

  std::error_code EC;
  llvm::raw_fd_ostream out(filename, EC);

  if (EC) {
    llvm::errs() << "Failed to open file '" << filename << "': " << EC.message()
                 << "\n";
    return;
  }

  M.print(out, nullptr);
}
static CallBase *pickCallSite(Function *F,
                              DenseMap<Function *, CallBase *> &memo) {
  auto it = memo.find(F);
  if (it != memo.end())
    return it->second;

  SmallVector<CallBase *, 4> candidates;
  for (User *U : F->users())
    if (auto *CB = dyn_cast<CallBase>(U))
      if (CB->getCalledFunction() == F)
        candidates.push_back(CB);

  if (candidates.empty()) {
    memo[F] = nullptr;
    return nullptr;
  }

  CallBase *chosen = candidates.front();
  bool viaOverride = false;

  if (candidates.size() > 1) {
    if (const char *pref = std::getenv("MBC_PREFER_CALLER")) {
      StringRef prefStr(pref);
      for (CallBase *CB : candidates) {
        if (CB->getFunction() &&
            CB->getFunction()->getName().contains(prefStr)) {
          chosen = CB;
          viaOverride = true;
          break;
        }
      }
    }

    errs() << "[!] '" << F->getName() << "' has " << candidates.size()
           << " call sites; picking the one in function '"
           << (chosen->getFunction() ? chosen->getFunction()->getName() : "?")
           << "'"
           << (viaOverride ? " (via MBC_PREFER_CALLER)"
                           : " (first found -- UNVERIFIED)")
           << ". This choice is reused for every trace that reaches '"
           << F->getName() << "'. All candidates:\n";
    for (CallBase *CB : candidates) {
      errs() << "      - in function '"
             << (CB->getFunction() ? CB->getFunction()->getName() : "?") << "'";
      if (DebugLoc DL = CB->getDebugLoc())
        errs() << " at line " << DL.getLine();
      errs() << (CB == chosen ? "  <-- chosen\n" : "\n");
    }
    if (!viaOverride)
      errs() << "    (set MBC_PREFER_CALLER=<substring of the correct "
                "caller's function name> to override this pick)\n";
  }

  memo[F] = chosen;
  return chosen;
}

static std::optional<uint64_t> inferAllocCallByteSize(CallInst *CI) {
  Function *Callee = CI->getCalledFunction();
  if (!Callee)
    return std::nullopt;
  StringRef Name = Callee->getName();

  auto asConst = [](Value *V) -> std::optional<uint64_t> {
    if (auto *CInt = dyn_cast<ConstantInt>(V))
      return CInt->getZExtValue();
    return std::nullopt;
  };

  if (Name == "calloc" && CI->arg_size() == 2) {
    auto nmemb = asConst(CI->getArgOperand(0));
    auto size = asConst(CI->getArgOperand(1));
    if (nmemb && size)
      return *nmemb * *size;
  } else if (Name == "malloc" && CI->arg_size() == 1) {
    return asConst(CI->getArgOperand(0));
  }
  return std::nullopt;
}

/// Trace a value backwards to its original AllocaInst, GlobalVariable, or
/// Constant.
Value *traceArgToRoot(Value *V, DenseMap<Function *, CallBase *> &memo) {
  std::set<Value *> visited;
  while (V && visited.insert(V).second) {
    if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
      V = GEP->getPointerOperand();
    } else if (auto *BC = dyn_cast<BitCastInst>(V)) {
      V = BC->getOperand(0);
    } else if (auto *Arg = dyn_cast<Argument>(V)) {
      Function *F = Arg->getParent();
      CallBase *CB = pickCallSite(F, memo);
      if (!CB)
        break;
      V = CB->getArgOperand(Arg->getArgNo());
    } else if (auto *LI = dyn_cast<LoadInst>(V)) {
      break;
    } else {
      break;
    }
  }
  return V;
}

unsigned inferPointerAllocSize(Argument *arg, unsigned defaultSize) {
  unsigned maxOffset = 0;
  bool foundGEP = false;

  std::function<void(Value *)> scanUsers = [&](Value *V) {
    for (User *U : V->users()) {
      if (auto *GEP = dyn_cast<GetElementPtrInst>(U)) {
        APInt offset(32, 0);
        if (GEP->accumulateConstantOffset(GEP->getModule()->getDataLayout(),
                                          offset)) {
          unsigned off = (unsigned)offset.getZExtValue();
          unsigned accessSize = off + 1;
          for (User *GU : GEP->users()) {
            if (auto *LI = dyn_cast<LoadInst>(GU)) {
              unsigned elemBytes =
                  LI->getModule()->getDataLayout().getTypeStoreSize(
                      LI->getType());
              accessSize = off + elemBytes;
            } else if (auto *SI = dyn_cast<StoreInst>(GU)) {
              if (SI->getPointerOperand() == GEP) {
                unsigned elemBytes =
                    SI->getModule()->getDataLayout().getTypeStoreSize(
                        SI->getValueOperand()->getType());
                accessSize = off + elemBytes;
              }
            }
          }
          if (accessSize > maxOffset) {
            maxOffset = accessSize;
            foundGEP = true;
          }
        }
        scanUsers(GEP);
      } else if (auto *BC = dyn_cast<BitCastInst>(U)) {
        scanUsers(BC);
      }
    }
  };

  scanUsers(arg);
  return foundGEP ? maxOffset : defaultSize;
}
// Inputs default to zero: every buffer is zero-filled and every scalar
// anchor starts at 0 (or at the constant the real call site passes, e.g. a
// length). The simulation overwrites them per trial; which arguments are
// secret / outputs comes from mayo.json, not from per-function testcases.
// Buffers keep their !llvmbmc.var name: the simulation's witness extractor
// locates them by it (no llvmbmc is run here).
void createDynamicDriverFunction(Module &OriginalM, Module &ExtractedM,
                                 Function *TargetF) {
  LLVMContext &ctx = ExtractedM.getContext();

  FunctionType *driverTy = FunctionType::get(Type::getInt32Ty(ctx), false);
  Function *driver = Function::Create(driverTy, GlobalValue::ExternalLinkage,
                                      "main", &ExtractedM);

  BasicBlock *entry = BasicBlock::Create(ctx, "entry", driver);
  IRBuilder<> builder(entry);
  DenseMap<Function *, CallBase *> callSiteMemo;
  std::vector<Value *> callArgs;

  Function *OrigF = OriginalM.getFunction(TargetF->getName());
  CallBase *FirstCall = OrigF ? pickCallSite(OrigF, callSiteMemo) : nullptr;

  for (unsigned i = 0; i < TargetF->arg_size(); i++) {
    Argument *arg = TargetF->getArg(i);
    Type *argTy = arg->getType();

    Value *root = nullptr;
    if (FirstCall) {
      root = traceArgToRoot(FirstCall->getArgOperand(i), callSiteMemo);
    }

    if (argTy->isPointerTy()) {
      Value *ptr = nullptr;
      uint64_t allocSize = 0;
      if (root) {
        if (auto *AI = dyn_cast<AllocaInst>(root)) {
          Type *allocTy = AI->getAllocatedType();
          std::string name = AI->getName().str();
          MDNode *N = MDNode::get(ctx, MDString::get(ctx, name));
          if (name.empty())
            name = "buf";
          AllocaInst *newAlloc = builder.CreateAlloca(allocTy, nullptr, name);
          newAlloc->setAlignment(Align(16));
          newAlloc->setMetadata("llvmbmc.var", N);
          allocSize = ExtractedM.getDataLayout().getTypeAllocSize(allocTy);
          builder.CreateMemSet(newAlloc, builder.getInt8(0), allocSize,
                               Align(1));

          ptr = builder.CreateBitCast(newAlloc, argTy);
          errs() << "  Arg " << i << " (" << arg->getName()
                 << "): alloca of type " << *allocTy << " named " << name
                 << "\n";
        } else if (auto *GV = dyn_cast<GlobalVariable>(root)) {
          Type *valTy = GV->getValueType();
          std::string name = GV->getName().str();
          MDNode *N = MDNode::get(ctx, MDString::get(ctx, name));
          if (name.empty())
            name = "buf";
          AllocaInst *newAlloc = builder.CreateAlloca(valTy, nullptr, name);
          newAlloc->setAlignment(Align(16));
          newAlloc->setMetadata("llvmbmc.var", N);
          allocSize = ExtractedM.getDataLayout().getTypeAllocSize(valTy);
          builder.CreateMemSet(newAlloc, builder.getInt8(0), allocSize,
                               Align(1));

          ptr = builder.CreateBitCast(newAlloc, argTy);
          errs() << "  Arg " << i << " (" << arg->getName()
                 << "): global of type " << *valTy << " named " << name << "\n";
        } else if (auto *CI = dyn_cast<CallInst>(root)) {
          // calloc/malloc with a constant size is an authoritative size
          // source; otherwise fall through to the GEP-scanning fallback.
          if (auto sizeOpt = inferAllocCallByteSize(CI)) {
            uint64_t byteSize = *sizeOpt;
            std::string name = "heap_" + std::to_string(byteSize);
            ArrayType *arrTy = ArrayType::get(Type::getInt8Ty(ctx), byteSize);
            AllocaInst *newAlloc = builder.CreateAlloca(arrTy, nullptr, name);
            MDNode *N = MDNode::get(ctx, MDString::get(ctx, name));
            newAlloc->setAlignment(Align(16));
            newAlloc->setMetadata("llvmbmc.var", N);
            allocSize = byteSize;
            builder.CreateMemSet(newAlloc, builder.getInt8(0), allocSize,
                                 Align(1));

            ptr = builder.CreateBitCast(newAlloc, argTy);
            errs() << "  Arg " << i << " (" << arg->getName()
                   << "): traced to heap allocation ("
                   << CI->getCalledFunction()->getName() << ") of " << byteSize
                   << " bytes\n";
          }
        }
      }

      if (!ptr) {
        unsigned fallbackSize = inferPointerAllocSize(arg, 128);
        ArrayType *arrTy = ArrayType::get(Type::getInt8Ty(ctx), fallbackSize);
        AllocaInst *alloc =
            builder.CreateAlloca(arrTy, nullptr, arg->getName() + "_buf");
        MDNode *N = MDNode::get(ctx, MDString::get(ctx, alloc->getName()));
        alloc->setAlignment(Align(16));
        alloc->setMetadata("llvmbmc.var", N);
        allocSize = fallbackSize;
        builder.CreateMemSet(alloc, builder.getInt8(0), allocSize, Align(1));

        ptr = builder.CreateBitCast(alloc, argTy);
        errs() << "  Arg " << i << " (" << arg->getName()
               << "): fallback -> alloca [" << allocSize << " x i8]\n";
      }
      callArgs.push_back(ptr);

    } else if (argTy->isIntegerTy()) {
      uint64_t initVal = 0;
      if (root && isa<ConstantInt>(root)) {
        initVal = cast<ConstantInt>(root)->getZExtValue();
      }

      // Must be a global, not a local alloca: a non-escaping local alloca
      // gets promoted to an SSA value by mem2reg and immediately constant-
      // folded by SCCP/InstCombine, silently reverting to a baked-in literal.
      // Mirrors __mbc_ret_anchor_* exactly, which is proven to survive the
      // same pipeline via volatile store/load.
      std::string anchorName =
          "__mbc_arg_" + TargetF->getName().str() + "_" + arg->getName().str();
      GlobalVariable *anchor = ExtractedM.getGlobalVariable(anchorName);
      if (!anchor) {
        anchor = new GlobalVariable(
            ExtractedM, argTy, /*isConstant=*/false,
            GlobalValue::ExternalLinkage,
            ConstantInt::get(argTy,
                             initVal), // baked as the GLOBAL's initializer
                                       // (lands in .data), not a runtime store
            anchorName);
      }
      Value *loaded =
          builder.CreateLoad(argTy, anchor, true, arg->getName() + "_val");
      callArgs.push_back(loaded);

      errs() << "  Arg " << i << " (" << arg->getName()
             << "): scalar backed by global anchor " << anchorName
             << ", init=" << initVal << "\n";
    } else {
      callArgs.push_back(Constant::getNullValue(argTy));
      errs() << "  Arg " << i << " (" << arg->getName()
             << "): unknown type -> null\n";
    }
  }

  CallInst *callI = builder.CreateCall(TargetF, callArgs);
  callI->setCallingConv(TargetF->getCallingConv());
  if (!TargetF->getReturnType()->isVoidTy() &&
      TargetF->getReturnType()->isIntegerTy()) {
    Type *retTy = TargetF->getReturnType();
    std::string anchorName = "__mbc_ret_anchor_" + TargetF->getName().str();
    GlobalVariable *anchor = ExtractedM.getGlobalVariable(anchorName);
    if (!anchor) {
      anchor = new GlobalVariable(ExtractedM, retTy, /*isConstant=*/false,
                                  GlobalValue::ExternalLinkage,
                                  Constant::getNullValue(retTy), anchorName);
    }
    builder.CreateStore(callI, anchor, /*isVolatile=*/true);
  }
  builder.CreateRet(builder.getInt32(0));

  // Prevent the driver from being optimized away or inlined
  driver->addFnAttr(Attribute::NoInline);
  driver->addFnAttr(Attribute::OptimizeNone);

  errs() << "Created driver function for " << TargetF->getName() << "\n";
}

std::unique_ptr<Module> extractFunction(Module &M, Function *F) {
  auto newMod = CloneModule(M);

  std::set<std::string> keep;
  keep.insert(F->getName().str());

  std::function<void(Function *)> collectCallees = [&](Function *fn) {
    for (auto &BB : *fn) {
      for (auto &I : BB) {
        if (auto *call = dyn_cast<CallInst>(&I)) {
          Function *callee = call->getCalledFunction();
          if (callee && !callee->isDeclaration()) {
            if (keep.insert(callee->getName().str()).second) {
              collectCallees(callee);
            }
          }
        }
      }
    }
  };
  collectCallees(F);

  for (auto it = newMod->begin(); it != newMod->end();) {
    Function &F2 = *it++;
    if (F2.isDeclaration())
      continue;
    if (keep.find(F2.getName().str()) == keep.end()) {
      if (F2.use_empty())
        F2.eraseFromParent();
      else
        F2.deleteBody();
    }
  }

  return newMod;
}
class DirectFuncSkip : public PassInfoMixin<DirectFuncSkip> {
  InstLocator loc;
  std::string targetFuncName;

public:
  DirectFuncSkip(InstLocator loc, std::string targetFuncName)
      : loc(loc), targetFuncName(std::move(targetFuncName)) {}
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    if (F.getName() != targetFuncName)
      return PreservedAnalyses::all();
    Instruction *I = findInstByLocator(F, loc);
    if (!I) {
      errs() << "No instruction found for locator (direct skip)\n";
      return PreservedAnalyses::all();
    }
    auto *CI = dyn_cast<CallInst>(I);
    if (!CI) {
      errs() << "Instruction at locator is not a CallInst\n";
      return PreservedAnalyses::all();
    }

    outs() << "Directly skipping call to "
           << (CI->getCalledFunction() ? CI->getCalledFunction()->getName()
                                       : "<indirect>")
           << "\n";
    Value *replacement = nullptr;
    if (!CI->getType()->isVoidTy()) {
      if (CI->arg_size() > 0 &&
          CI->getArgOperand(0)->getType() == CI->getType()) {
        replacement = CI->getArgOperand(0);
      } else {
        replacement = Constant::getNullValue(CI->getType());
        // or: IRBuilder<>(CI).CreateZExtOrTrunc(CI->getArgOperand(0),
        // CI->getType());
      }
    }
    if (replacement)
      CI->replaceAllUsesWith(replacement);
    CI->eraseFromParent();

    return PreservedAnalyses::none();
  }
};

class LabeledUnrollPass : public PassInfoMixin<LabeledUnrollPass> {
  static constexpr unsigned long long kMaxTotalUnrollBudget =
      200000; // tune this
  unsigned long long budgetUsed = 0;

  static unsigned long long loopBlockCount(Loop *L) {
    return L->getNumBlocks();
  }

public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {

    std::vector<BasicBlock *> headers;
    for (Loop *L : FAM.getResult<LoopAnalysis>(F))
      headers.push_back(L->getHeader());

    for (BasicBlock *header : headers) {

      FAM.invalidate(F, PreservedAnalyses::none());
      auto &LI = FAM.getResult<LoopAnalysis>(F);
      auto &SE = FAM.getResult<ScalarEvolutionAnalysis>(F);

      Loop *L = LI.getLoopFor(header);
      if (!L)
        continue; // defensive; shouldn't happen for an untouched sibling loop

      unsigned tripCount = SE.getSmallConstantTripCount(L);
      if (tripCount == 0) {
        errs() << "cannot determine trip count\n";
        continue;
      }
      if (tripCount > kMaxUnrollTripCount) {
        errs() << "Loop trip count " << tripCount << " exceeds max ("
               << kMaxUnrollTripCount << "); skipping unroll for this loop\n";
        continue;
      }

      unsigned long long cost =
          (unsigned long long)tripCount * loopBlockCount(L);
      if (budgetUsed + cost > kMaxTotalUnrollBudget) {
        errs() << "Skipping loop (trip count " << tripCount << ", "
               << loopBlockCount(L) << " blocks/iter): "
               << "would exceed total unroll budget (" << budgetUsed << "/"
               << kMaxTotalUnrollBudget << ")\n";
        continue;
      }
      budgetUsed += cost;
      errs() << "Loop trip count: " << tripCount << "\n";
      addLabelNUnroll(F, L, LI, SE, tripCount);
    }
    return PreservedAnalyses::none();
  }

  void addLabelNUnroll(Function &F, Loop *L, LoopInfo &LI, ScalarEvolution &SE,
                       unsigned tripCount) {
    BasicBlock *header = L->getHeader();
    BasicBlock *latch = L->getLoopLatch();
    BasicBlock *preheader = L->getLoopPreheader();
    BasicBlock *exitBB = L->getUniqueExitBlock();

    if (!header || !latch || !preheader || !exitBB) {
      errs() << "Loop not in simplified form\n";
      return;
    }

    std::vector<BasicBlock *> origBlocks;
    for (BasicBlock *BB : L->blocks()) {
      origBlocks.push_back(BB);
    }

    BasicBlock *prevIterExit = preheader;
    ValueToValueMapTy cumulativeMap;

    for (unsigned i = 0; i < tripCount; i++) {
      // 1. Create start label
      BasicBlock *iterStart = BasicBlock::Create(
          F.getContext(), "iter_" + std::to_string(i) + "_start", &F);

      // 2. Resolve PHI nodes for this iteration
      std::vector<std::pair<PHINode *, Value *>> resolvedPhis;
      for (PHINode &PN : header->phis()) {
        Value *incoming;
        if (i == 0) {
          incoming = PN.getIncomingValueForBlock(preheader);
        } else {
          Value *latchVal = PN.getIncomingValueForBlock(latch);
          if (Value *mapped = cumulativeMap.lookup(latchVal))
            incoming = mapped;
          else
            incoming = latchVal;
        }
        cumulativeMap[&PN] = incoming;
        resolvedPhis.push_back({&PN, incoming});
      }

      // 3. Clone all blocks for this iteration
      std::vector<BasicBlock *> iterationCloned;
      ValueToValueMapTy iterationBlockMap;
      for (BasicBlock *BB : origBlocks) {
        BasicBlock *cloned =
            CloneBasicBlock(BB, cumulativeMap, ".iter" + std::to_string(i), &F);
        iterationCloned.push_back(cloned);
        iterationBlockMap[BB] = cloned;

        // Map individual instructions to their clones
        auto itOrig = BB->begin();
        auto itCloned = cloned->begin();
        while (itOrig != BB->end() && itCloned != cloned->end()) {
          iterationBlockMap[&*itOrig] = &*itCloned;
          // For next iteration's use
          cumulativeMap[&*itOrig] = &*itCloned;
          itOrig++;
          itCloned++;
        }
      }

      // 4. Resolve internal control flow in the cloned iteration
      for (BasicBlock *cloned : iterationCloned) {
        for (Instruction &I : *cloned) {
          RemapInstruction(&I, iterationBlockMap,
                           RF_NoModuleLevelChanges | RF_IgnoreMissingLocals);
        }
      }

      // 5. Remove PHI nodes from the cloned header as they are now resolved
      for (auto &pair : resolvedPhis) {
        PHINode *origPhi = pair.first;
        Value *resolvedVal = pair.second;
        if (Value *clonedPhiVal = iterationBlockMap.lookup(origPhi)) {
          PHINode *clonedPhi = cast<PHINode>(clonedPhiVal);
          clonedPhi->replaceAllUsesWith(resolvedVal);
          clonedPhi->eraseFromParent();
        }
      }

      // 6. Create end label
      BasicBlock *iterEnd = BasicBlock::Create(
          F.getContext(), "iter_" + std::to_string(i) + "_end", &F);

      // 7. Connect control flow
      if (i == 0) {
        Instruction *prevTerm = preheader->getTerminator();
        BranchInst::Create(iterStart, preheader);
        prevTerm->eraseFromParent();
      } else {
        BranchInst::Create(iterStart, prevIterExit);
      }

      BranchInst::Create(iterationCloned.front(), iterStart);

      BasicBlock *clonedLatch = cast<BasicBlock>(iterationBlockMap[latch]);
      Instruction *latchTerm = clonedLatch->getTerminator();
      BranchInst::Create(iterEnd, clonedLatch);
      latchTerm->eraseFromParent();

      prevIterExit = iterEnd;
    }

    BranchInst::Create(exitBB, prevIterExit);
    for (auto it = exitBB->begin(); isa<PHINode>(it);) {
      PHINode *PN = cast<PHINode>(&*it++);
      Value *incomingVal = nullptr;

      for (unsigned j = 0; j < PN->getNumIncomingValues(); j++) {
        if (L->contains(PN->getIncomingBlock(j))) {
          incomingVal = PN->getIncomingValue(j);
          break;
        }
      }

      if (!incomingVal)
        continue;

      if (Value *mapped = cumulativeMap.lookup(incomingVal))
        incomingVal = mapped;

      while (true) {
        bool removed = false;
        for (unsigned j = 0; j < PN->getNumIncomingValues(); j++) {
          if (L->contains(PN->getIncomingBlock(j))) {
            PN->removeIncomingValue(j, false);
            removed = true;
            break;
          }
        }
        if (!removed)
          break;
      }

      PN->addIncoming(incomingVal, prevIterExit);
    }
    for (BasicBlock *BB : origBlocks) {
      BB->eraseFromParent();
    }
    // NOTE: Do NOT manually erase origBlocks here.
    // The original loop blocks are now unreachable and will be safely removed
    // by subsequent DCE passes (GlobalDCEPass, ADCEPass, DCEPass).
    // Manually erasing them causes memory corruption because LLVM's internal
    // data structures (like LoopInfo) still reference these blocks.
  }
};

Function *getOrCloneHelper(Module &M, Module &SourceM, StringRef Name) {

  if (Function *F = M.getFunction(Name))
    return F;

  Function *Src = SourceM.getFunction(Name);
  if (!Src)
    return nullptr;

  ValueToValueMapTy VMap;

  Function *NewF = Function::Create(Src->getFunctionType(), Src->getLinkage(),
                                    Src->getName(), &M);

  auto DestI = NewF->arg_begin();
  for (const Argument &Arg : Src->args()) {
    DestI->setName(Arg.getName());
    VMap[&Arg] = &*DestI++;
  }

  SmallVector<ReturnInst *, 8> Returns;

  CloneFunctionInto(NewF, Src, VMap, CloneFunctionChangeType::DifferentModule,
                    Returns);

  return NewF;
}

void replaceMemoryIntrinsics(Module &M, Module &SourceM) {

  Function *MayoMemset = getOrCloneHelper(M, SourceM, "mayo_memset");

  Function *MayoMemcpy = getOrCloneHelper(M, SourceM, "mayo_memcpy");

  SmallVector<CallInst *, 64> Worklist;

  for (Function &F : M) {
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {

        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI)
          continue;

        Function *Callee = CI->getCalledFunction();

        if (!Callee || !Callee->isIntrinsic())
          continue;

        Intrinsic::ID ID = Callee->getIntrinsicID();

        if (ID == Intrinsic::memset || ID == Intrinsic::memcpy)
          Worklist.push_back(CI);
      }
    }
  }

  for (CallInst *CI : Worklist) {

    IRBuilder<> B(CI);

    Function *Callee = CI->getCalledFunction();

    switch (Callee->getIntrinsicID()) {

    case Intrinsic::memset: {

      auto *MSI = cast<MemSetInst>(CI);

      B.CreateCall(MayoMemset,
                   {MSI->getDest(), MSI->getValue(),
                    B.CreateIntCast(MSI->getLength(),
                                    Type::getInt32Ty(M.getContext()), false)});

      CI->eraseFromParent();
      break;
    }

    case Intrinsic::memcpy: {

      auto *MCI = cast<MemCpyInst>(CI);

      B.CreateCall(MayoMemcpy,
                   {MCI->getDest(), MCI->getSource(),
                    B.CreateIntCast(MCI->getLength(),
                                    Type::getInt32Ty(M.getContext()), false)});

      CI->eraseFromParent();
      break;
    }

    default:
      break;
    }
  }
}

void cleanup(Module &M) {
  for (auto FI = M.begin(); FI != M.end();) {

    Function &F = *FI++;

    if (F.isDeclaration() && F.use_empty())
      F.eraseFromParent();
  }
  for (auto GI = M.global_begin(); GI != M.global_end();) {
    GlobalVariable *GV = &*GI++;
    if (GV->use_empty())
      GV->eraseFromParent();
  }
}
int main(int argc, char **argv) {
  if (argc < 3) {
    errs() << "Usage: ./loop_fn_Fault <input.ll> <mode> [funcName] [funcToSkip "
              "| line]\n";
    errs() << "0 => loopSkip\n";
    errs() << "1 => funcSkip (funcToSkip arg is a line number into the taint "
              "JSON)\n";
    return 1;
  }

  std::string inputFile = argv[1];
  int mode = std::stoi(argv[2]);
  std::string funcName = "main";
  std::string funcToSkipArg = "";
  if (argc >= 5) {
    funcName = argv[3];
    funcToSkipArg = argv[4];
  }
  LLVMContext ctx;
  SMDiagnostic err;
  auto module = parseIRFile(inputFile, err, ctx);
  if (!module) {
    err.print("Input File not found", errs());
    return 1;
  }

  Function *target = module->getFunction(funcName);
  if (!target) {
    std::cout << "Target Function not found: " << funcName << std::endl;
    return 1;
  }
  int skipLine = -1;
  if (mode == FUNC_SKIP) {
    if (funcToSkipArg.empty()) {
      errs() << "FUNC_SKIP mode requires a line number as the 4th arg\n";
      return 1;
    }
    skipLine = std::stoi(funcToSkipArg);
  }

  auto funcModule = extractFunction(*module, target);
  if (!funcModule) {
    std::cout << "Failed to create extracted module" << std::endl;
    return 1;
  }

  if (Function *F = funcModule->getFunction(funcName))
    F->setLinkage(GlobalValue::ExternalLinkage);

  {
    Function *extractedFunc = funcModule->getFunction(funcName);
    if (extractedFunc) {
      errs() << "Creating driver function for " << funcName << "...\n";
      createDynamicDriverFunction(*module, *funcModule, extractedFunc);
    }
  }

  // --- Resolve the target call site & whether it's inside a loop ---

  InstLocator skipLoc;
  bool callInsideLoop = false;
  std::string skippedCalleeName;

  if (mode == FUNC_SKIP) {
    Function *preOptF = funcModule->getFunction(funcName);
    if (!preOptF) {
      errs() << "Function not found in extracted module: " << funcName << "\n";
      return 1;
    }
    Instruction *origInst = getInstByIndex(*preOptF, skipLine);
    if (!origInst) {
      errs() << "No instruction found at line " << skipLine
             << " in extracted (pre-optimization) function\n";
      return 1;
    }
    auto *origCall = dyn_cast<CallInst>(origInst);
    if (!origCall) {
      errs() << "Instruction at line " << skipLine << " is not a CallInst ("
             << origInst->getOpcodeName()
             << "); funcSkip requires a CallInst\n";
      return 1;
    }
    skippedCalleeName = origCall->getCalledFunction()
                            ? origCall->getCalledFunction()->getName().str()
                            : "<indirect>";
    skipLoc = captureInstLocator(origInst, skipLine);
    if (!skipLoc.hasDbg) {
      errs() << "Warning: call at line " << skipLine
             << " has no debug location; re-lookup after unrolling may be "
                "unreliable.\n";
    }

    LoopAnalysisManager LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager CGAM;
    ModuleAnalysisManager MAM;
    PassBuilder PB;
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    auto &LI = FAM.getResult<LoopAnalysis>(*preOptF);
    callInsideLoop = (LI.getLoopFor(origCall->getParent()) != nullptr);

    errs() << "Call to " << skippedCalleeName << " at line " << skipLine
           << " is " << (callInsideLoop ? "inside" : "NOT inside")
           << " a loop.\n";
  }

  auto makePB = [&](Module &M, auto buildPipeline) {
    LoopAnalysisManager LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager CGAM;
    ModuleAnalysisManager MAM;
    PassBuilder PB;
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    ModulePassManager MPM;
    buildPipeline(MPM);
    MPM.run(M, MAM);
  };

  std::unique_ptr<Module> preUnrollClone;
  if (mode == FUNC_SKIP) {
    preUnrollClone = CloneModule(*funcModule);
  }

  // Unroll for original.ll
  for (Function &F : *funcModule) {
    F.removeFnAttr(Attribute::NoInline);
    F.removeFnAttr(Attribute::OptimizeNone);
    if (!F.isDeclaration())
      F.addFnAttr(Attribute::InlineHint);
  }

  makePB(*funcModule, [](ModulePassManager &MPM) {
    // {
    //   InlineParams IP;
    //   IP.DefaultThreshold = 10000;
    //   MPM.addPass(ModuleInlinerPass(IP));
    // }
    // Constant-prop + simplify
    {
      FunctionPassManager FPM;
      FPM.addPass(PromotePass());
      FPM.addPass(SCCPPass());
      FPM.addPass(CorrelatedValuePropagationPass());
      FPM.addPass(InstCombinePass());
      FPM.addPass(SimplifyCFGPass());
      MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
    }
    // Loop unroll (no fault)
    {
      FunctionPassManager FPM;
      FPM.addPass(LoopSimplifyPass());
      FPM.addPass(LCSSAPass());
      FPM.addPass(createFunctionToLoopPassAdaptor(LoopRotatePass()));
      FPM.addPass(createFunctionToLoopPassAdaptor(IndVarSimplifyPass()));
      FPM.addPass(LabeledUnrollPass());
      FPM.addPass(SCCPPass());
      FPM.addPass(PromotePass());
      MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
    }
    MPM.addPass(GlobalOptPass());
  });
  replaceMemoryIntrinsics(*funcModule, *module);
  cleanup(*funcModule);
  {
    LoopAnalysisManager LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager CGAM;
    ModuleAnalysisManager MAM;

    PassBuilder PB;

    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    ModulePassManager MPM;

    MPM.addPass(GlobalDCEPass());

    FunctionPassManager FPM;
    FPM.addPass(ADCEPass());
    FPM.addPass(DCEPass());

    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

    MPM.run(*funcModule, MAM);
  }
  // StripDebugInfo(*funcModule);

  if (verifyModule(*funcModule, &errs())) {
    errs() << "Invalid IR after LabeledUnrollPass\n";
    return 1;
  }
  std::string original = "../../test_mayo/" + funcName + "/" + funcName + ".ll";

  dump_module(*funcModule, original);
  outs() << "Wrote" << original << "\n";

  // Clone and inject fault
  std::string faultyFile =
      "../../test_mayo/" + funcName + "/loopOrFuncSkip/" + funcName;
  std::string outFile;
  if (mode == LOOP_SKIP) {
    auto faultModule = CloneModule(*funcModule);
    // stripOutputAssertions(*faultModule);
    unsigned skipIter = 1;
    Function *faultFunc = faultModule->getFunction(funcName);
    if (faultFunc) {
      std::string srcName = "iter_" + std::to_string(skipIter - 1) + "_end";
      std::string newTarget = "iter_" + std::to_string(skipIter + 1) + "_start";
      std::string skippedSuffix = ".iter" + std::to_string(skipIter);
      std::string prevSuffix = ".iter" + std::to_string(skipIter - 1);

      std::string skipStartName = "iter_" + std::to_string(skipIter) + "_start";
      std::string skipEndName = "iter_" + std::to_string(skipIter) + "_end";

      std::vector<BasicBlock *> skippedBlocks;
      BasicBlock *srcBB = nullptr, *newTargetBB = nullptr;
      bool inSkipped = false;

      for (BasicBlock &BB : *faultFunc) {
        if (BB.getName() == srcName)
          srcBB = &BB;
        if (BB.getName() == newTarget)
          newTargetBB = &BB;
        if (BB.getName() == skipStartName)
          inSkipped = true;
        if (inSkipped)
          skippedBlocks.push_back(&BB);
        if (BB.getName() == skipEndName)
          inSkipped = false;
      }

      if (srcBB && newTargetBB) {

        std::map<Value *, Value *> remap;
        for (BasicBlock *BB : skippedBlocks) {
          for (Instruction &I : *BB) {
            std::string iName = I.getName().str();
            if (iName.empty())
              continue;

            size_t pos = iName.rfind(skippedSuffix);
            if (pos == std::string::npos)
              continue;

            std::string prevName = iName.substr(0, pos) + prevSuffix;
            for (BasicBlock &searchBB : *faultFunc) {
              for (Instruction &searchI : searchBB) {
                if (searchI.getName() == prevName) {
                  remap[&I] = &searchI;
                  break;
                }
              }
              if (remap.count(&I))
                break;
            }
          }
        }

        // Replace uses of skipped-iteration values outside the skipped blocks
        for (auto &[skippedVal, prevVal] : remap) {
          std::vector<Use *> usesToReplace;
          for (Use &U : skippedVal->uses()) {
            Instruction *user = dyn_cast<Instruction>(U.getUser());
            if (!user)
              continue;
            BasicBlock *userBB = user->getParent();
            bool isInSkipped = false;
            for (BasicBlock *sBB : skippedBlocks) {
              if (sBB == userBB) {
                isInSkipped = true;
                break;
              }
            }
            if (!isInSkipped)
              usesToReplace.push_back(&U);
          }
          for (Use *U : usesToReplace)
            U->set(prevVal);
        }

        // Redirect the branch from iter_(N-1)_end to iter_(N+1)_start
        Instruction *term = srcBB->getTerminator();
        if (auto *br = dyn_cast<BranchInst>(term)) {
          BranchInst::Create(newTargetBB, srcBB);
          br->eraseFromParent();
          outs() << "Fault injected: " << srcName << " -> " << newTarget
                 << " (skipping iteration " << skipIter << ")\n";
        }

        for (BasicBlock *BB : skippedBlocks)
          BB->dropAllReferences();
        for (BasicBlock *BB : skippedBlocks)
          BB->eraseFromParent();

      } else {
        errs() << "Could not find blocks for fault injection\n";
      }
    }

    if (verifyModule(*faultModule, &errs())) {
      errs() << "Fault module has invalid IR\n";
    } else {
      outFile = faultyFile + "_loopSkip.ll";
      dump_module(*faultModule, outFile);
      outs() << "Wrote " << outFile << "\n";
    }

  } else if (mode == FUNC_SKIP) {
    for (Function &F : *preUnrollClone) {
      F.removeFnAttr(Attribute::NoInline);
      F.removeFnAttr(Attribute::OptimizeNone);
      if (!F.isDeclaration())
        F.addFnAttr(Attribute::InlineHint);
    }

    makePB(*preUnrollClone, [&](ModulePassManager &MPM) {
      if (callInsideLoop) {
        FunctionPassManager FPM;
        FPM.addPass(LoopSimplifyPass());
        FPM.addPass(LCSSAPass());
        FPM.addPass(createFunctionToLoopPassAdaptor(LoopRotatePass()));
        FPM.addPass(createFunctionToLoopPassAdaptor(IndVarSimplifyPass()));
        FPM.addPass(FuncSkip(skipLoc, funcName));
        FPM.addPass(SCCPPass());
        FPM.addPass(PromotePass());
        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

        // InlineParams IP;
        // IP.DefaultThreshold = 10000;
        // MPM.addPass(ModuleInlinerPass(IP));
      } else {
        FunctionPassManager FPM;
        FPM.addPass(DirectFuncSkip(skipLoc, funcName));
        FPM.addPass(PromotePass());
        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

        // InlineParams IP;
        // IP.DefaultThreshold = 10000;
        // MPM.addPass(ModuleInlinerPass(IP));
      }

      MPM.addPass(GlobalOptPass());
    });
    replaceMemoryIntrinsics(*preUnrollClone, *module);
    cleanup(*preUnrollClone);
    {
      LoopAnalysisManager LAM;
      FunctionAnalysisManager FAM;
      CGSCCAnalysisManager CGAM;
      ModuleAnalysisManager MAM;

      PassBuilder PB;

      PB.registerModuleAnalyses(MAM);
      PB.registerCGSCCAnalyses(CGAM);
      PB.registerFunctionAnalyses(FAM);
      PB.registerLoopAnalyses(LAM);
      PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

      ModulePassManager MPM;

      MPM.addPass(GlobalDCEPass());

      FunctionPassManager FPM;
      FPM.addPass(ADCEPass());
      FPM.addPass(DCEPass());

      MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

      MPM.run(*preUnrollClone, MAM);
    }
    // StripDebugInfo(*preUnrollClone);
    if (verifyModule(*preUnrollClone, &errs())) {
      errs() << "Fault module has invalid IR\n";
    } else {
      outFile = faultyFile + "_fnSkip_" + skippedCalleeName + "_line" +
                std::to_string(skipLine) + ".ll";
      dump_module(*preUnrollClone, outFile);
      outs() << "Wrote " << outFile << "\n";
    }

  } else {
    errs() << "Invalid mode. Use 0 or 1\n";
    return 1;
  }

  // No faulty .ll was written (its module failed verification above).
  if (outFile.empty()) {
    errs() << "No faulty variant written for " << funcName << " line "
           << skipLine << "\n";
    return 1;
  }
  return 0;
}