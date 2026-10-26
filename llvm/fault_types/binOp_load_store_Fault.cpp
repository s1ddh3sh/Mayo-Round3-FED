#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>

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
#include "llvm/Transforms/Utils/ValueMapper.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <set>

using namespace llvm;
static constexpr unsigned kMaxUnrollTripCount = 2000;

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
      BasicBlock *iterStart = BasicBlock::Create(
          F.getContext(), "iter_" + std::to_string(i) + "_start", &F);

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

      std::vector<BasicBlock *> iterationCloned;
      ValueToValueMapTy iterationBlockMap;
      for (BasicBlock *BB : origBlocks) {
        BasicBlock *cloned =
            CloneBasicBlock(BB, cumulativeMap, ".iter" + std::to_string(i), &F);
        iterationCloned.push_back(cloned);
        iterationBlockMap[BB] = cloned;

        auto itOrig = BB->begin();
        auto itCloned = cloned->begin();
        while (itOrig != BB->end() && itCloned != cloned->end()) {
          iterationBlockMap[&*itOrig] = &*itCloned;
          cumulativeMap[&*itOrig] = &*itCloned;
          itOrig++;
          itCloned++;
        }
      }

      for (BasicBlock *cloned : iterationCloned) {
        for (Instruction &I : *cloned) {
          RemapInstruction(&I, iterationBlockMap,
                           RF_NoModuleLevelChanges | RF_IgnoreMissingLocals);
        }
      }

      for (auto &pair : resolvedPhis) {
        PHINode *origPhi = pair.first;
        Value *resolvedVal = pair.second;
        if (Value *clonedPhiVal = iterationBlockMap.lookup(origPhi)) {
          PHINode *clonedPhi = cast<PHINode>(clonedPhiVal);
          clonedPhi->replaceAllUsesWith(resolvedVal);
          clonedPhi->eraseFromParent();
        }
      }

      BasicBlock *iterEnd = BasicBlock::Create(
          F.getContext(), "iter_" + std::to_string(i) + "_end", &F);

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

enum class FaultModel { Undef, Zero, OpB, OpA, Mem };
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
  unsigned fallbackIndex = 0; // used only if no debug info is available
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

static bool isFirstIterationBlock(const BasicBlock &BB) {
  StringRef name = BB.getName();
  if (name == "iter_0_start" || name == "iter_0_end")
    return true;
  if (name.ends_with(".iter0"))
    return true;
  return false;
}
static bool matchesTargetKind(Instruction *I, bool wantBinOp,
                              bool wantLoadOrStore) {
  if (wantBinOp)
    return isa<BinaryOperator>(I);
  if (wantLoadOrStore)
    return isa<LoadInst>(I) || isa<StoreInst>(I);
  return true;
}

static Instruction *findInstByLocator(Function &F, const InstLocator &loc,
                                      bool wantBinOp, bool wantLoadOrStore) {
  if (loc.hasDbg) {
    Instruction *firstIterMatch = nullptr;
    Instruction *anyMatch = nullptr;

    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        DebugLoc DL = I.getDebugLoc();
        if (!DL || DL.getLine() != loc.dbgLine || DL.getCol() != loc.dbgCol)
          continue;
        if (!matchesTargetKind(&I, wantBinOp, wantLoadOrStore))
          continue;
        if (!anyMatch)
          anyMatch = &I;
        if (!firstIterMatch && isFirstIterationBlock(BB))
          firstIterMatch = &I;
      }
    }

    if (firstIterMatch)
      return firstIterMatch;

    if (anyMatch) {
      return anyMatch;
    }
    errs() << "Warning: no instruction with debug loc " << loc.dbgLine << ":"
           << loc.dbgCol << " found; falling back to index "
           << loc.fallbackIndex << "\n";
  }
  return getInstByIndex(F, loc.fallbackIndex);
}

class FaultInjectionPass : public PassInfoMixin<FaultInjectionPass> {
  FaultModel FM;
  InstLocator loc;
  static std::string valueName(Value *V) {
    if (V->hasName())
      return "%" + V->getName().str();
    std::string s;
    raw_string_ostream os(s);
    V->printAsOperand(os, false);
    return os.str();
  }

  static Instruction *getInst(Function &F, unsigned targetInst) {
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

public:
  explicit FaultInjectionPass(FaultModel FM, InstLocator loc)
      : FM(FM), loc(loc) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {

    bool modified = false;

    bool wantBinOp = (FM != FaultModel::Mem);
    bool wantLoadOrStore = (FM == FaultModel::Mem);

    Instruction *I = findInstByLocator(F, loc, wantBinOp, wantLoadOrStore);
    // outs() << *I;
    if (!I) {
      errs() << "No instruction found for locator\n";
      // errs() << M;
      return PreservedAnalyses::all();
    }
    if (auto *binOp = dyn_cast<BinaryOperator>(I)) {

      Type *ty = binOp->getType();

      Value *faulty = nullptr;

      switch (FM) {
      case FaultModel::Undef:
        faulty = UndefValue::get(ty);
        binOp->replaceAllUsesWith(faulty);
        binOp->eraseFromParent();
        modified = true;
        break;
      case FaultModel::Zero:
        faulty = ConstantInt::get(ty, 0);
        binOp->replaceAllUsesWith(faulty);
        binOp->eraseFromParent();
        modified = true;
        break;
      case FaultModel::OpB:
        binOp->setOperand(0, ConstantInt::get(ty, 0));
        modified = true;
        break;
      case FaultModel::OpA:
        binOp->setOperand(1, ConstantInt::get(ty, 0));
        modified = true;
        break;
      case FaultModel::Mem:
        break;
      }
    } else if (auto *load = dyn_cast<LoadInst>(I)) {
      if (FM == FaultModel::Mem) {
        Type *ty = load->getType();
        Value *faulty = Constant::getNullValue(ty);
        load->replaceAllUsesWith(faulty);
        load->eraseFromParent();
        modified = true;
      }
    } else if (auto *store = dyn_cast<StoreInst>(I)) {
      if (FM == FaultModel::Mem) {
        store->eraseFromParent();
        modified = true;
      }
    }

    if (modified)
      return PreservedAnalyses::none();
    else
      return PreservedAnalyses::all();
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

  if (argc < 4) {
    std::cerr << "Usage: ./binOpFault <input.ll> <function> <line>\n";
    return 1;
  }

  std::string inputFile = argv[1];
  std::string funcName = argv[2];
  int line = atoi(argv[3]);
  LLVMContext ctx;
  SMDiagnostic err;

  auto module = parseIRFile(inputFile, err, ctx);
  if (!module) {
    err.print("error", errs());
    return 1;
  }

  Function *target = module->getFunction(funcName);
  if (!target) {
    errs() << "Function  not found in input module\n";
    errs() << "Available functions:\n";
    for (Function &F : *module) {
      errs() << "  " << F.getName() << (F.isDeclaration() ? " [decl]" : "")
             << "\n";
    }
    return 1;
  }

  auto funcModule = extractFunction(*module, target);
  if (!funcModule) {
    errs() << "Failed to create extracted module\n";
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

  Function *preOptF = funcModule->getFunction(funcName);
  if (!preOptF) {
    errs() << "Function not found in extracted module: " << funcName << "\n";
    return 1;
  }
  Instruction *origInst = getInstByIndex(*preOptF, line);
  if (!origInst) {
    errs() << "No instruction found at line " << line
           << " in extracted (pre-optimization) function\n";
    return 1;
  }
  // Decide the fault category from the ORIGINAL instruction, before any
  // transformation can change its opcode or position.
  bool isBinOp = isa<BinaryOperator>(origInst);
  bool isLoadOrStore = isa<LoadInst>(origInst) || isa<StoreInst>(origInst);

  if (!isBinOp && !isLoadOrStore) {
    errs() << "Instruction at line " << line
           << " is neither BinOp, LoadInst, nor StoreInst ("
           << origInst->getOpcodeName() << "); skipping fault injection\n";
    return 0;
  }

  InstLocator sourceLoc = captureInstLocator(origInst, line);
  if (!sourceLoc.hasDbg) {
    errs() << "Warning: instruction at line " << line
           << " has no debug location; post-optimization re-lookup will "
              "fall back to raw index and may be unreliable.\n";
  }

  // outs() << *funcModule;
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
  // outs() << *funcModule;
  if (verifyModule(*funcModule, &errs())) {
    errs() << "Invalid IR\n";
    return 1;
  }
  Function *postPipelineF = funcModule->getFunction(funcName);
  if (!postPipelineF) {
    errs() << "Function not found in post-pipeline module: " << funcName
           << "\n";
    return 1;
  }
  Instruction *postPipelineInst =
      findInstByLocator(*postPipelineF, sourceLoc, isBinOp, isLoadOrStore);
  if (!postPipelineInst) {
    errs() << "Could not re-locate target instruction after unroll/optimize "
              "pipeline (source line "
           << line << ")\n";
    return 1;
  }
  InstLocator locator =
      captureInstLocator(postPipelineInst, /*fallbackIndex=*/0);

  std::string filename = "../../test_mayo/" + funcName + "/";
  dump_module(*funcModule, filename + funcName + ".ll");
  outs() << "Wrote " << filename << funcName << ".ll\n";

  // auto mod = parseIRFile("original.ll", err, ctx);
  // outs() << *funcModule;

  struct FaultEntry {
    FaultModel model;
    const char *name;
  };

  std::vector<FaultEntry> faults;
  std::string faultSubdir;
  if (isBinOp) {
    faults = {
        {FaultModel::Undef, "undef"},
        {FaultModel::Zero, "zero"},
        {FaultModel::OpB, "opB"},
        {FaultModel::OpA, "opA"},
    };
    faultSubdir = "binOpFault/";
  } else { // isLoadOrStore
    faults = {
        {FaultModel::Mem, "mem"},
    };
    faultSubdir = "loadStoreSkip/";
  }
  bool failed = false;
  for (auto &fe : faults) {

    auto cloned = CloneModule(*funcModule);
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

    FunctionPassManager FPM;
    FPM.addPass(PromotePass());
    FPM.addPass(FaultInjectionPass(fe.model, locator));
    Function *TargetF = cloned->getFunction(funcName);

    if (!TargetF) {
      errs() << "Function not found: " << funcName << "\n";
      continue;
    }

    FPM.run(*TargetF, FAM);

    std::string llFile = filename + faultSubdir + funcName + "_line" + argv[3] +
                         "_" + fe.name + ".ll";

    if (verifyModule(*cloned, &errs())) {
      errs() << "Fault module has invalid IR (" << fe.name << "); not writing "
             << llFile << "\n";
      failed = true;
      continue;
    }
    dump_module(*cloned, llFile);
    outs() << "Wrote " << llFile << "\n";
  }

  return failed ? 1 : 0;
}