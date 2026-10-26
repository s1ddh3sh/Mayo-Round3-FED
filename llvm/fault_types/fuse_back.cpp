//===- fuseback_gated.cpp ------------------------------------------------===//
//
// Take a full-MAYO base module and a single faulted variant of one function,
// and emit a module in which:
//
//   * the faulted body is imported under the name  <funcName>__faulted
//     (the original <funcName> is kept intact),
//   * every call site of <funcName> is replaced by a runtime gate that
//     dispatches the TARGET occurrence to <funcName>__faulted and every other
//     occurrence to the original,
//   * a `main` calling the signature entry exists (synthesised if absent).
//
// The faulted variant already bakes in exactly one fault on its first internal
// iteration, so the only selection left is which dynamic CALL occurrence to
// fault -- that is the counter gate. Default target occurrence = 1 (matches the
// correction attack, which targets s_0).
//
// Usage:
//   ./fuseback_gated <base.ll> <faulted_function.ll> <functionName>
//                    [entryFunctionName] [targetOccurrence]
//
//   entryFunctionName defaults to pqmayo_MAYO_1_ref_mayo_sign_signature
//   targetOccurrence  defaults to 1
//
// Run once per faulted variant file.
//===----------------------------------------------------------------------===//

#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace llvm;

static const char *DEFAULT_ENTRY = "pqmayo_MAYO_1_ref_mayo_sign_signature";

//===----------------------------------------------------------------------===//
// dependency import (unchanged from your fuseback.cpp)
//===----------------------------------------------------------------------===//

static GlobalValue *
resolveOrImportGlobal(GlobalValue *GV, Module &DestM,
                      DenseMap<GlobalValue *, GlobalValue *> &Imported);

static Function *
importFunction(Function *SrcFn, Module &DestM,
               DenseMap<GlobalValue *, GlobalValue *> &Imported) {
  if (auto it = Imported.find(SrcFn); it != Imported.end())
    return cast<Function>(it->second);

  if (Function *Existing = DestM.getFunction(SrcFn->getName())) {
    Imported[SrcFn] = Existing;
    return Existing;
  }

  Function *NewFn = Function::Create(
      SrcFn->getFunctionType(), SrcFn->getLinkage(), SrcFn->getName(), &DestM);
  NewFn->copyAttributesFrom(SrcFn);
  Imported[SrcFn] = NewFn;

  if (SrcFn->isDeclaration())
    return NewFn;

  ValueToValueMapTy VMap;
  auto destArgIt = NewFn->arg_begin();
  for (Argument &SrcArg : SrcFn->args()) {
    if (SrcArg.hasName())
      destArgIt->setName(SrcArg.getName());
    VMap[&SrcArg] = &*destArgIt;
    ++destArgIt;
  }

  for (auto &BB : *SrcFn)
    for (auto &I : BB)
      for (Use &U : I.operands())
        if (auto *InnerGV = dyn_cast<GlobalValue>(U.get()))
          if (!VMap.count(InnerGV))
            VMap[InnerGV] = resolveOrImportGlobal(InnerGV, DestM, Imported);

  SmallVector<ReturnInst *, 8> Returns;
  CloneFunctionInto(NewFn, SrcFn, VMap,
                    CloneFunctionChangeType::DifferentModule, Returns);
  return NewFn;
}

static GlobalValue *
resolveOrImportGlobal(GlobalValue *GV, Module &DestM,
                      DenseMap<GlobalValue *, GlobalValue *> &Imported) {
  if (auto it = Imported.find(GV); it != Imported.end())
    return it->second;

  if (auto *Fn = dyn_cast<Function>(GV))
    return importFunction(Fn, DestM, Imported);

  if (auto *GVar = dyn_cast<GlobalVariable>(GV)) {
    if (GlobalVariable *Existing =
            DestM.getGlobalVariable(GVar->getName(), true)) {
      Imported[GV] = Existing;
      return Existing;
    }
    auto *NewGV = new GlobalVariable(DestM, GVar->getValueType(),
                                     GVar->isConstant(), GVar->getLinkage(),
                                     /*Initializer=*/nullptr, GVar->getName());
    NewGV->copyAttributesFrom(GVar);
    Imported[GV] = NewGV;
    if (GVar->hasInitializer())
      errs() << "Warning: global '" << GVar->getName()
             << "' initializer not transferred (should already exist in base).\n";
    return NewGV;
  }

  errs() << "Warning: unsupported global value '" << GV->getName()
         << "' left unresolved.\n";
  return GV;
}

//===----------------------------------------------------------------------===//
// import the faulted body under a fresh name (does NOT reuse an existing one)
//===----------------------------------------------------------------------===//

static Function *
importRenamed(Function *SrcFn, Module &DestM, const std::string &NewName,
              DenseMap<GlobalValue *, GlobalValue *> &Imported) {
  Function *NewFn = Function::Create(SrcFn->getFunctionType(),
                                     SrcFn->getLinkage(), NewName, &DestM);
  NewFn->copyAttributesFrom(SrcFn);

  ValueToValueMapTy VMap;
  auto destArgIt = NewFn->arg_begin();
  for (Argument &SrcArg : SrcFn->args()) {
    if (SrcArg.hasName())
      destArgIt->setName(SrcArg.getName());
    VMap[&SrcArg] = &*destArgIt;
    ++destArgIt;
  }

  for (auto &BB : *SrcFn)
    for (auto &I : BB)
      for (Use &U : I.operands())
        if (auto *GV = dyn_cast<GlobalValue>(U.get()))
          if (!VMap.count(GV))
            VMap[GV] = resolveOrImportGlobal(GV, DestM, Imported);

  SmallVector<ReturnInst *, 8> Returns;
  CloneFunctionInto(NewFn, SrcFn, VMap, CloneFunctionChangeType::DifferentModule,
                    Returns);
  return NewFn;
}

//===----------------------------------------------------------------------===//
// occurrence-gated call-site dispatch
//===----------------------------------------------------------------------===//

static void gateCallSites(Module &M, Function *Orig, Function *Faulted,
                          GlobalVariable *Cnt, GlobalVariable *Tgt) {
  LLVMContext &Ctx = M.getContext();
  Type *I32 = Type::getInt32Ty(Ctx);

  // Collect first; we mutate the CFG as we go.
  std::vector<CallInst *> Sites;
  for (Function &F : M) {
    if (&F == Faulted)
      continue; // never gate the faulted body's own calls
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *CI = dyn_cast<CallInst>(&I))
          if (CI->getCalledFunction() == Orig)
            Sites.push_back(CI);
  }

  for (CallInst *CI : Sites) {
    Function *Par = CI->getFunction();
    BasicBlock *BB = CI->getParent();

    // Split so that CI (and everything after) lands in Cont.
    BasicBlock *Cont = BB->splitBasicBlock(CI, "fi.cont");
    BB->getTerminator()->eraseFromParent(); // remove the auto-inserted br

    IRBuilder<> B(BB);
    Value *C = B.CreateLoad(I32, Cnt, "fi.c");
    Value *C1 = B.CreateAdd(C, ConstantInt::get(I32, 1), "fi.c1");
    B.CreateStore(C1, Cnt);
    Value *T = B.CreateLoad(I32, Tgt, "fi.t");
    Value *Armed = B.CreateICmpEQ(C1, T, "fi.armed");

    BasicBlock *FB = BasicBlock::Create(Ctx, "fi.faulted", Par, Cont);
    BasicBlock *OB = BasicBlock::Create(Ctx, "fi.orig", Par, Cont);
    B.CreateCondBr(Armed, FB, OB);

    SmallVector<Value *, 8> Args(CI->arg_begin(), CI->arg_end());

    IRBuilder<> BF(FB);
    CallInst *FC = BF.CreateCall(Faulted->getFunctionType(), Faulted, Args);
    FC->setCallingConv(CI->getCallingConv());
    FC->setAttributes(CI->getAttributes());
    FC->setDebugLoc(CI->getDebugLoc());
    BF.CreateBr(Cont);

    IRBuilder<> BO(OB);
    CallInst *OC = BO.CreateCall(Orig->getFunctionType(), Orig, Args);
    OC->setCallingConv(CI->getCallingConv());
    OC->setAttributes(CI->getAttributes());
    OC->setDebugLoc(CI->getDebugLoc());
    BO.CreateBr(Cont);

    if (!CI->getType()->isVoidTy()) {
      IRBuilder<> BC(CI);
      PHINode *Phi = BC.CreatePHI(CI->getType(), 2, "fi.res");
      Phi->addIncoming(FC, FB);
      Phi->addIncoming(OC, OB);
      CI->replaceAllUsesWith(Phi);
    }
    CI->eraseFromParent();
  }

  errs() << "gate: dispatched " << Sites.size() << " call site(s) of "
         << Orig->getName() << "\n";
}

//===----------------------------------------------------------------------===//
// ensure a main that calls the signature entry
//===----------------------------------------------------------------------===//

static GlobalVariable *getExternI32(Module &M, StringRef Name) {
  if (auto *G = M.getGlobalVariable(Name, true))
    return G;
  Type *I32 = Type::getInt32Ty(M.getContext());
  auto *G = new GlobalVariable(M, I32, /*isConstant=*/false,
                               GlobalValue::ExternalLinkage,
                               /*Init=*/nullptr, Name);
  G->setAlignment(Align(4));
  return G;
}

static void ensureMain(Module &M, Function *Entry) {
  if (M.getFunction("main"))
    return; // keep the existing (BMC) main
  LLVMContext &Ctx = M.getContext();
  Type *I32 = Type::getInt32Ty(Ctx);
  Type *I8 = Type::getInt8Ty(Ctx);
  Type *Ptr = PointerType::getUnqual(Ctx);

  FunctionCallee Memset =
      M.getOrInsertFunction("mayo_memset", Type::getVoidTy(Ctx), Ptr, I8, I32);

  std::string EN = Entry->getName().str();
  GlobalVariable *ArgMlen = getExternI32(M, "__mbc_arg_" + EN + "_mlen");
  GlobalVariable *RetAnchor = getExternI32(M, "__mbc_ret_anchor_" + EN);

  Function *MainF = Function::Create(FunctionType::get(I32, false),
                                     GlobalValue::ExternalLinkage, "main", &M);
  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", MainF);
  IRBuilder<> B(BB);

  auto mkBuf = [&](unsigned N, const char *Nm) -> AllocaInst * {
    ArrayType *AT = ArrayType::get(I8, N);
    AllocaInst *A = B.CreateAlloca(AT, nullptr, Nm);
    A->setAlignment(Align(16));
    B.CreateCall(Memset, {A, B.getInt8(0), B.getInt32(N)});
    return A;
  };

  AllocaInst *PBuf = mkBuf(128, "p_buf");
  AllocaInst *SigBuf = mkBuf(431, "sig_buf");
  AllocaInst *SigLen = B.CreateAlloca(I32, nullptr, "siglen");
  SigLen->setAlignment(Align(16));
  B.CreateStore(B.getInt32(0), SigLen);
  AllocaInst *MBuf = mkBuf(128, "m_buf");
  LoadInst *Mlen = B.CreateLoad(I32, ArgMlen, "mlen_val");
  Mlen->setVolatile(true);
  Mlen->setAlignment(Align(4));
  AllocaInst *Heap24 = mkBuf(24, "heap_24");

  CallInst *Ret =
      B.CreateCall(Entry->getFunctionType(), Entry,
                   {PBuf, SigBuf, SigLen, MBuf, Mlen, Heap24});
  StoreInst *SR = B.CreateStore(Ret, RetAnchor);
  SR->setVolatile(true);
  SR->setAlignment(Align(4));
  B.CreateRet(B.getInt32(0));

  errs() << "main: synthesised, calling " << EN
         << " (note: !llvmbmc.var metadata not attached -- keep your own main "
            "if the BMC needs it)\n";
}

//===----------------------------------------------------------------------===//

static void dumpModule(Module &M, const std::string &filename) {
  SmallString<256> path(filename);
  sys::path::remove_filename(path);
  if (!path.empty())
    if (std::error_code EC = sys::fs::create_directories(path)) {
      errs() << "Failed to create directories: " << EC.message() << "\n";
      return;
    }
  std::error_code EC;
  raw_fd_ostream out(filename, EC);
  if (EC) {
    errs() << "Failed to open '" << filename << "': " << EC.message() << "\n";
    return;
  }
  M.print(out, nullptr);
}

int main(int argc, char **argv) {
  if (argc < 4 || argc > 6) {
    std::cerr << "Usage: ./fuseback_gated <base.ll> <faulted_function.ll> "
                 "<functionName> [entryFunctionName] [targetOccurrence]\n";
    return 1;
  }
  std::string baseFile = argv[1];
  std::string fnFile = argv[2];
  std::string funcName = argv[3];
  std::string entryName = (argc >= 5) ? argv[4] : DEFAULT_ENTRY;
  unsigned targetOcc = (argc >= 6) ? std::stoul(argv[5]) : 1u;

  LLVMContext ctx;
  SMDiagnostic err;

  auto baseModule = parseIRFile(baseFile, err, ctx);
  if (!baseModule) {
    errs() << "Error parsing base IR: " << baseFile << "\n";
    err.print(argv[0], errs());
    return 1;
  }
  auto fnModule = parseIRFile(fnFile, err, ctx);
  if (!fnModule) {
    errs() << "Error parsing function IR: " << fnFile << "\n";
    err.print(argv[0], errs());
    return 1;
  }

  Function *SrcF = fnModule->getFunction(funcName);
  if (!SrcF || SrcF->isDeclaration()) {
    errs() << "Error: '" << funcName << "' not defined in " << fnFile << "\n";
    return 1;
  }
  Function *Orig = baseModule->getFunction(funcName);
  if (!Orig) {
    errs() << "Error: '" << funcName << "' not present in " << baseFile << "\n";
    return 1;
  }
  if (SrcF->getFunctionType() != Orig->getFunctionType())
    errs() << "Warning: type mismatch for '" << funcName
           << "'; gate dispatch may be invalid.\n";

  Function *Entry = baseModule->getFunction(entryName);
  if (!Entry) {
    errs() << "Error: entry '" << entryName << "' not present in base\n";
    return 1;
  }

  // 1. main first, so its call to the entry is gate-eligible when funcName==entry
  ensureMain(*baseModule, Entry);

  // 2. import faulted body under a fresh name (shared callees are reused)
  std::string faultedName = funcName + "__faulted";
  unsigned uniq = 0;
  while (baseModule->getNamedValue(faultedName))
    faultedName = funcName + "__faulted" + std::to_string(++uniq);
  DenseMap<GlobalValue *, GlobalValue *> imported;
  Function *Faulted = importRenamed(SrcF, *baseModule, faultedName, imported);
  errs() << "import: faulted body added as '" << faultedName << "'\n";

  // 3. gate globals
  Type *I32 = Type::getInt32Ty(ctx);
  std::string safe = funcName;
  for (char &c : safe)
    if (!std::isalnum((unsigned char)c) && c != '_')
      c = '_';
  auto *Cnt = new GlobalVariable(*baseModule, I32, false,
                                 GlobalValue::InternalLinkage,
                                 ConstantInt::get(I32, 0), "__fi_count_" + safe);
  Cnt->setAlignment(Align(4));
  auto *Tgt = new GlobalVariable(
      *baseModule, I32, false, GlobalValue::InternalLinkage,
      ConstantInt::get(I32, targetOcc), "__fi_target_" + safe);
  Tgt->setAlignment(Align(4));

  // 4. rewrite call sites
  gateCallSites(*baseModule, Orig, Faulted, Cnt, Tgt);

  // 5. verify + write
  std::string verr;
  raw_string_ostream vs(verr);
  if (verifyModule(*baseModule, &vs))
    errs() << "Warning: module failed verification:\n"
           << vs.str() << "(inspect output manually)\n";

  SmallString<256> outDir(sys::path::parent_path(fnFile));
  sys::path::append(outDir, "full_mayo_gated");
  if (std::error_code EC = sys::fs::create_directories(outDir)) {
    errs() << "Failed to create output dir: " << EC.message() << "\n";
    return 1;
  }
  std::string outName = "gated_" + sys::path::stem(fnFile).str() + ".ll";
  SmallString<256> outFile(outDir);
  sys::path::append(outFile, outName);
  dumpModule(*baseModule, outFile.str().str());
  outs() << "Wrote " << outFile << "\n";
  return 0;
}