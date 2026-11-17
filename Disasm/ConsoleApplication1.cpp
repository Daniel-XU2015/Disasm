#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>
#include <unordered_map>
#include <algorithm>
#include <thread>
#include <atomic>
#include <functional>
#include <cerrno>

#include "Zydis.h"

// =====================================================================
// 基础类型
// =====================================================================
struct Insn {
    uint64_t addr = 0;
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
};

struct PCodeStmt {
    std::string op;
    std::string dst, src1, src2;
    uint64_t jumpTarget = 0;
    uint64_t addr = 0;
};

struct BasicBlock {
    int id = 0;
    uint64_t startAddr = 0, endAddr = 0;
    std::vector<PCodeStmt> pcode;
    std::vector<int> successors;
    std::vector<int> predecessors;
    int idom = -1;
    bool isLoopHeader = false;
    std::vector<int> loopBody;
};

struct Function {
    uint64_t startAddr = 0;
    std::string name;
    std::vector<BasicBlock> blocks;
    bool isDead = true;
    bool isLibraryFunc = false;
    std::string libFuncName;
    std::string generatedCode;
};

// =====================================================================
// ApiResolver
// =====================================================================
class ApiResolver {
    std::unordered_map<uint64_t, std::string> m_iat;
public:
    void LoadImports(const uint8_t* fileData, size_t fileSize, const IMAGE_NT_HEADERS* nt, uint64_t imageBase) {
        uint32_t rva = 0;
        if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            rva = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        else
            rva = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (!rva) return;
        const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(RvaToOff(fileData, fileSize, nt, rva));
        if (!desc) return;
        while (desc->Name) {
            const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
                RvaToOff(fileData, fileSize, nt, desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
            uint32_t thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            const uint8_t* thunkBytes = RvaToOff(fileData, fileSize, nt, thunkRva);
            if (!thunkBytes) { ++desc; continue; }
            uint64_t iat = imageBase + desc->FirstThunk;
            while (thunk && thunk->u1.AddressOfData) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
            bool is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            for (size_t k = 0;; ++k) {
                uint64_t entry = is64
                    ? reinterpret_cast<const IMAGE_THUNK_DATA64*>(thunkBytes)[k].u1.AddressOfData
                    : reinterpret_cast<const IMAGE_THUNK_DATA32*>(thunkBytes)[k].u1.AddressOfData;
                if (!entry) break;
                uint64_t ordinalFlag = is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
                if (!(entry & ordinalFlag)) {
                    const auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        RvaToOff(fileData, fileSize, nt, thunk->u1.AddressOfData));
                    if (ibn) m_iat[iat] = std::string(ibn->Name);
                        RvaToOff(fileData, fileSize, nt, static_cast<uint32_t>(entry)));
                    if (ibn) m_iat[iat] = std::string(reinterpret_cast<const char*>(ibn->Name));
                }
                iat += (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 4 : 8;
                thunk++;
                iat += is64 ? 8 : 4;
            }
            desc++;
        }
    }
    std::string GetApiName(uint64_t addr) const {
        auto it = m_iat.find(addr);
        return it != m_iat.end() ? it->second : "";
    }
private:
    static const uint8_t* RvaToOff(const uint8_t* f, size_t sz, const IMAGE_NT_HEADERS* nt, uint32_t rva) {
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
                uint32_t o = rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
                return o < sz ? f + o : nullptr;
            }
        return nullptr;
    }
};

// =====================================================================
// 模块 1: Xref
// =====================================================================
struct Xref {
    uint64_t from, to;
    enum Kind { CALL_FUNC, CALL_API, JUMP } kind;
    std::string detail;
};

class XrefDB {
    std::unordered_map<uint64_t, std::vector<Xref>> m_to;
public:
    void Add(const Xref& e) { m_to[e.to].push_back(e); }
    std::string CallersOf(uint64_t f) const {
        std::string s;
        auto it = m_to.find(f);
        if (it != m_to.end()) for (auto& x : it->second)
            if (x.kind == Xref::CALL_FUNC) s += "0x" + Hex(x.from) + " ";
        return s;
    }
    static std::string Hex(uint64_t v) {
        char b[32]; sprintf_s(b, "%llx", (unsigned long long)v); return b;
    }
};

// =====================================================================
// 模块 2: TypeRecovery
// =====================================================================
class TypeRecovery {
    struct F { uint32_t off; std::string name; };
    std::unordered_map<std::string, std::vector<F>> m_st;
public:
    TypeRecovery() {
        m_st["_DRIVER_OBJECT"] = { { 0x00,"Type" },{ 0x02,"Size" },{ 0x08,"DeviceObject" },{ 0x10,"Flags" },
                                        { 0x18,"DriverStart" },{ 0x20,"DriverSize" },{ 0x30,"DriverExtension" },
                                        { 0x38,"DriverName" },{ 0x68,"DriverUnload" },{ 0x70,"MajorFunction" } };
        m_st["_DEVICE_OBJECT"] = { { 0x00,"Type" },{ 0x02,"Size" },{ 0x04,"ReferenceCount" },{ 0x08,"DriverObject" },
                                        { 0x10,"NextDevice" },{ 0x18,"AttachedDevice" },{ 0x20,"CurrentIrp" },
                                        { 0x30,"Flags" },{ 0x40,"DeviceExtension" },{ 0x48,"DeviceType" },{ 0x4c,"StackSize" } };
        m_st["_IRP"] = { { 0x00,"Type" },{ 0x02,"Size" },{ 0x08,"MdlAddress" },{ 0x18,"Flags" },
                                        { 0x30,"IoStatus" },{ 0x38,"RequestorMode" },{ 0x40,"PendingReturned" },
                                        { 0x48,"UserIosb" },{ 0x58,"UserEvent" },{ 0x68,"CancelRoutine" } };
        m_st["_IO_STACK_LOCATION"] = { { 0x00,"MajorFunction" },{ 0x01,"MinorFunction" },{ 0x08,"Flags" },
                                        { 0x18,"Parameters" },{ 0x20,"DeviceObject" },{ 0x28,"FileObject" } };
        m_st["_UNICODE_STRING"] = { { 0x00,"Length" },{ 0x02,"MaximumLength" },{ 0x08,"Buffer" } };
    }
    std::string CandidatesFor(int32_t off) const {
        std::string r;
        for (auto& kv : m_st) for (auto& f : kv.second)
            if ((int32_t)f.off == off) {
                if (!r.empty()) r += ", ";
                r += kv.first + "." + f.name;
            }
        return r;
    }
    static bool ParseMem(const std::string& s, std::string& base, int32_t& off) {
        if (s.size() < 4 || s.compare(0, 4, "MEM(")) return false;
        auto lp = s.find('('), rp = s.rfind(')');
        if (lp == std::string::npos || rp == std::string::npos) return false;
        std::string inner = s.substr(lp + 1, rp - lp - 1);
        auto p = inner.find_first_of("+-");
        if (p == std::string::npos) { base = inner; off = 0; return true; }
        base = inner.substr(0, p);
        try { off = std::stoi(inner.substr(p)); }
        catch (...) { return false; }
        return true;
    }
};

// =====================================================================
// 模块 3: DataFlow（块内常量传播）
// =====================================================================
class DataFlow {
    static bool IsConst(const std::string& s) {
        return s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
    }
    static std::string Canon(const std::string& r) {
        static const std::unordered_map<std::string, std::string> M = {
            { "eax","rax" },{ "ax","rax" },{ "al","rax" },{ "ah","rax" },
            { "ebx","rbx" },{ "bx","rbx" },{ "bl","rbx" },{ "bh","rbx" },
            { "ecx","rcx" },{ "cx","rcx" },{ "cl","rcx" },{ "ch","rcx" },
            { "edx","rdx" },{ "dx","rdx" },{ "dl","rdx" },{ "dh","rdx" },
            { "esi","rsi" },{ "si","rsi" },{ "sil","rsi" },
            { "edi","rdi" },{ "di","rdi" },{ "dil","rdi" },
            { "ebp","rbp" },{ "bp","rbp" },{ "bpl","rbp" },
            { "esp","rsp" },{ "sp","rsp" },{ "spl","rsp" },
            { "r8d","r8" },{ "r8w","r8" },{ "r8b","r8" },
            { "r9d","r9" },{ "r9w","r9" },{ "r9b","r9" },
            { "r10d","r10" },{ "r11d","r11" },{ "r12d","r12" },
            { "r13d","r13" },{ "r14d","r14" },{ "r15d","r15" } };
        auto it = M.find(r);
        return it != M.end() ? it->second : r;
    }
public:
    void Run(Function& func) {
        for (auto& blk : func.blocks) {
            std::unordered_map<std::string, std::string> regs;
            for (auto& s : blk.pcode) {
                if (s.op == "MOV" && IsConst(s.src1))
                    regs[Canon(s.dst)] = s.src1;
                else if (s.op == "MOV" && regs.count(Canon(s.src1)))
                    s.src1 = regs[Canon(s.src1)];
                else if (s.op == "ALU" && regs.count(Canon(s.src2)))
                    s.src2 = regs[Canon(s.src2)];
                else if (s.op == "CMP" && regs.count(Canon(s.src1)))
                    s.src1 = regs[Canon(s.src1)];
                // 修复 Bug#7: MOV 也清空目标寄存器缓存
                if (!s.dst.empty()) regs.erase(Canon(s.dst));
                if (s.op == "CALL") regs.clear();
            }
        }
    }
};

// =====================================================================
// 模块 4: DynamicApiResolver
// =====================================================================
class DynamicApiResolver {
public:
    void Analyze(Function& func, const std::unordered_map<uint64_t, std::string>& strings) const {
        auto resolveString = [&](const std::string& v) -> std::string {
            if (v.rfind("STR_", 0) != 0) return "";
            uint64_t a = strtoull(v.c_str() + 4, nullptr, 16);
            auto it = strings.find(a);
            return it != strings.end() ? it->second : "";
        };

        for (auto& blk : func.blocks) {
            std::string pendingStr;
            for (size_t i = 0; i < blk.pcode.size(); ++i) {
                auto& s = blk.pcode[i];
                if (s.op == "LEA" && s.src1.find("STR_") == 0) {
                    uint64_t a = strtoull(s.src1.substr(4).c_str(), nullptr, 16);
                    auto it = strings.find(a);
                    if (it != strings.end()) pendingStr = it->second;

                if ((s.op == "LEA" || s.op == "MOV") && !s.src1.empty()) {
                    std::string resolved = resolveString(s.src1);
                    if (!resolved.empty()) {
                        pendingStr = resolved;
                        continue;
                    }
                if (s.op == "CALL" && s.src1.find("GetProcAddress") != std::string::npos
                    && !pendingStr.empty()) {
                    for (size_t j = i + 1; j < blk.pcode.size() && j < i + 5; ++j) {
                }

                if (s.op == "CALL") {
                    std::string callee = s.src1;
                    if (callee.find("GetProcAddress") != std::string::npos ||
                        callee.find("LdrGetProcedureAddress") != std::string::npos) {
                        if (!pendingStr.empty()) {
                            for (size_t j = i + 1; j < blk.pcode.size() && j < i + 6; ++j) {
                                auto& n = blk.pcode[j];
                        if (n.op == "CALL" && (n.src1 == "rax" || n.src1 == "rcx" ||
                            n.src1 == "rdx" || n.src1 == "r8" ||
                            n.src1 == "r9")) {
                                if (n.op == "CALL" &&
                                    (n.src1 == "rax" || n.src1 == "rcx" || n.src1 == "rdx" ||
                                     n.src1 == "r8"  || n.src1 == "r9" || n.src1 == "qword ptr [rax]")) {
                                    n.src1 = "api_" + pendingStr;
                                    break;
                                }
                            }
                        }
                        pendingStr.clear();
                        continue;
                    }

                    if ((callee.find("LoadLibrary") != std::string::npos ||
                         callee.find("LoadLibraryEx") != std::string::npos ||
                         callee.find("GetModuleHandle") != std::string::npos) &&
                        !pendingStr.empty()) {
                        s.src1 = "api_" + pendingStr;
                        pendingStr.clear();
                        continue;
                    }

                    if (!pendingStr.empty() &&
                        (s.src1 == "rax" || s.src1 == "rcx" || s.src1 == "rdx" ||
                         s.src1 == "r8"  || s.src1 == "r9")) {
                        s.src1 = "api_" + pendingStr;
                        pendingStr.clear();
                    }

                    if (!pendingStr.empty()) pendingStr.clear();
                }
            }
        }
    }
};

// =====================================================================
// 模块 5: FunctionCFG（真正实现）
// =====================================================================
class FunctionCFG {
public:
    void Build(Function& func) {
        if (func.blocks.empty() || func.blocks[0].pcode.empty()) return;
        Split(func);
        Connect(func);
        Dominators(func);
        Loops(func);
    }
private:
    // 修复 Bug#1: 按 leader 切块
    static void Split(Function& func) {
        std::set<uint64_t> leaders;
        leaders.insert(func.blocks[0].pcode[0].addr);
        for (auto& blk : func.blocks) for (size_t i = 0; i < blk.pcode.size(); ++i) {
            auto& s = blk.pcode[i];
            if (s.op == "JMP" || s.op == "CJMP") {
                if (s.jumpTarget) leaders.insert(s.jumpTarget);
                if (i + 1 < blk.pcode.size()) leaders.insert(blk.pcode[i + 1].addr);
            }
            if (s.op == "RET" && i + 1 < blk.pcode.size())
                leaders.insert(blk.pcode[i + 1].addr);
        }
        std::vector<BasicBlock> nb;
        BasicBlock* cur = nullptr;
        for (auto& blk : func.blocks) for (auto& s : blk.pcode) {
            if (leaders.count(s.addr) || !cur) {
                BasicBlock b; b.id = (int)nb.size(); b.startAddr = s.addr;
                nb.push_back(b); cur = &nb.back();
            }
            cur->pcode.push_back(s); cur->endAddr = s.addr;
        }
        func.blocks = std::move(nb);
    }
    static void Connect(Function& func) {
        std::map<uint64_t, int> id;
        for (auto& b : func.blocks) id[b.startAddr] = b.id;
        for (auto& b : func.blocks) {
            if (b.pcode.empty()) continue;
            auto& last = b.pcode.back();
            auto link = [&](int t) {
                if (t < 0 || t >= (int)func.blocks.size()) return;
                if (t == b.id) return;
                for (int x : b.successors) if (x == t) return;
                b.successors.push_back(t);
                func.blocks[t].predecessors.push_back(b.id);
            };
            auto fallthrough = [&]() {
                if (b.id + 1 >= (int)func.blocks.size()) return;
                auto& nextBlk = func.blocks[b.id + 1];
                if (nextBlk.startAddr <= b.endAddr) return;
                link(b.id + 1);
            };
            if (last.op == "JMP" && last.jumpTarget) {
                auto it = id.find(last.jumpTarget);
                if (it != id.end()) link(it->second);
            }
            else if (last.op == "CJMP" && last.jumpTarget) {
                auto it = id.find(last.jumpTarget);
                if (it != id.end()) link(it->second);
                link(b.id + 1);
                fallthrough();
            }
            else if (last.op != "RET") link(b.id + 1);
            else if (last.op != "RET") fallthrough();
        }
    }
    // 修复 Bug#2: CHK 算法
    static void Dominators(Function& func) {
        int N = (int)func.blocks.size();
        if (!N) return;
        std::vector<int> rpo; std::vector<bool> vis(N, false);
        std::function<void(int)> dfs = [&](int b) {
            vis[b] = true;
            for (int s : func.blocks[b].successors) if (!vis[s]) dfs(s);
            rpo.push_back(b);
            };
        dfs(0);
        std::reverse(rpo.begin(), rpo.end());
        std::vector<int> num(N, -1);
        for (int i = 0; i < (int)rpo.size(); ++i) num[rpo[i]] = i;
        auto inter = [&](int a, int b) {
            while (a != b) {
                while (num[a] > num[b]) a = func.blocks[a].idom;
                while (num[b] > num[a]) b = func.blocks[b].idom;
            }
            return a;
            };
        func.blocks[0].idom = 0;
        bool ch = true;
        while (ch) {
            ch = false;
            for (int b : rpo) {
                if (b == 0) continue;
                int ni = -1;
                for (int p : func.blocks[b].predecessors) {
                    if (func.blocks[p].idom == -1) continue;
                    ni = (ni == -1) ? p : inter(p, ni);
                }
                if (ni != -1 && func.blocks[b].idom != ni) {
                    func.blocks[b].idom = ni; ch = true;
                }
            }
        }
    }
    // 修复 Bug#3: 循环检测加终止条件
    static void Loops(Function& func) {
        for (auto& blk : func.blocks) for (int s : blk.successors) {
            if (s < 0 || s >= (int)func.blocks.size()) continue;
            int c = blk.id; bool back = false;
            std::set<int> seen;
            while (c >= 0 && !seen.count(c)) {
                seen.insert(c);
                if (c == s) { back = true; break; }
                int id = func.blocks[c].idom;
                if (id == c || id < 0) break;
                c = id;
            }
            if (!back) continue;
            func.blocks[s].isLoopHeader = true;
            std::set<int> body{ s };
            std::vector<int> stk{ blk.id };
            while (!stk.empty()) {
                int x = stk.back(); stk.pop_back();
                if (x < 0 || x >= (int)func.blocks.size()) continue;
                if (!body.count(x)) {
                    body.insert(x);
                    for (int p : func.blocks[x].predecessors)
                        if (!body.count(p)) stk.push_back(p);
                }
            }
            func.blocks[s].loopBody.assign(body.begin(), body.end());
        }
    }
};

// =====================================================================
// 模块 6: CompilableEmitter（结构化）
// =====================================================================
class CompilableEmitter {
public:
    void EmitPreamble(std::ostream& out, const std::set<std::string>& usedApis) {
        out << "// Auto-generated: compile-only skeleton, NOT equivalent.\n";
        out << "#include <windows.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n";
        out << "#pragma warning(disable: 4100 4189 4244 4245 4267 4311 4312 4700)\n\n";
        out << R"REG(
typedef uintptr_t u64p;
typedef union { uint64_t q; uint32_t d; uint16_t w; struct { uint8_t l, h; }; } reg64_t;
static reg64_t rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8,r9,r10,r11,r12,r13,r14,r15;
static int zflag = 0, sflag = 0;
#define eax rax.d
#define ax  rax.w
#define al  rax.l
#define ebx rbx.d
#define bx  rbx.w
#define bl  rbx.l
#define ecx rcx.d
#define cx  rcx.w
#define cl  rcx.l
#define edx rdx.d
#define dx  rdx.w
#define dl  rdx.l
#define esi rsi.d
#define si  rsi.w
#define sil rsi.l
#define edi rdi.d
#define di  rdi.w
#define dil rdi.l
#define ebp rbp.d
#define bp  rbp.w
#define bpl rbp.l
#define esp rsp.d
#define sp  rsp.w
#define spl rsp.l
#define r8d  r8.d
#define r8w  r8.w
#define r8b  r8.l
#define r9d  r9.d
#define r9w  r9.w
#define r9b  r9.l
#define r10d r10.d
#define r10w r10.w
#define r10b r10.l
#define r11d r11.d
#define r11w r11.w
#define r11b r11.l
#define r12d r12.d
#define r12w r12.w
#define r12b r12.l
#define r13d r13.d
#define r13w r13.w
#define r13b r13.l
#define r14d r14.d
#define r14w r14.w
#define r14b r14.l
#define r15d r15.d
#define r15w r15.w
#define r15b r15.l
)REG";
        out << "\n#define MEM_POOL_SIZE (1u << 24)\nstatic uint8_t g_mem[MEM_POOL_SIZE];\n";
        out << "#define GA(p)   (g_mem + ((uint32_t)(p) & (MEM_POOL_SIZE-1)))\n";
        out << "#define MEM8(p)  (*(volatile uint8_t  *)GA(p))\n";
        out << "#define MEM16(p) (*(volatile uint16_t *)GA(p))\n";
        out << "#define MEM32(p) (*(volatile uint32_t *)GA(p))\n";
        out << "#define MEM64(p) (*(volatile uint64_t *)GA(p))\n";
        out << "#define MEM(p)   MEM64(p)\n\n";
        out << R"API(
typedef uint64_t (*generic_pfn_t)(uint64_t,uint64_t,uint64_t,uint64_t);
static uint64_t ResolveApi(const char* name) {
    static HMODULE hK = LoadLibraryA("kernel32.dll");
    static HMODULE hN = GetModuleHandleA("ntdll.dll");
    static HMODULE hU = LoadLibraryA("user32.dll");
    static HMODULE hA = LoadLibraryA("advapi32.dll");
    static HMODULE hK = NULL;
    static HMODULE hN = NULL;
    static HMODULE hU = NULL;
    static HMODULE hA = NULL;
    static const struct { const char* mod; HMODULE* h; } D[] = {
        {"kernel32.dll",&hK},{"ntdll.dll",&hN},{"user32.dll",&hU},{"advapi32.dll",&hA} };
    for (auto& d : D) {
        HMODULE h = *d.h;
        if (!h) h = LoadLibraryA(d.mod);
    for (size_t i = 0; i < sizeof(D) / sizeof(D[0]); ++i) {
        HMODULE h = *D[i].h;
        if (!h) h = LoadLibraryA(D[i].mod);
        if (!h) continue;
        FARPROC p = GetProcAddress(h, name);
        if (p) return (uint64_t)p;
    }
    return 0;
}
#define API_CALL(name, a1, a2, a3, a4) \
    do { static uint64_t _p = 0; \
         if (!_p) _p = ResolveApi(name); \
         if (_p) rax.q = ((generic_pfn_t)_p)((uint64_t)(a1),(uint64_t)(a2),(uint64_t)(a3),(uint64_t)(a4)); \
    } while (0)
)API";
        out << R"CALL(
static uint64_t CallIndirect(uint64_t target, uint64_t a1, uint64_t a2,
                             uint64_t a3, uint64_t a4) {
    if (!target) return 0;
    return ((generic_pfn_t)target)(a1, a2, a3, a4);
}
static void UnknownInstruction(uint64_t address) {
    (void)address;
}
)CALL";
        if (!usedApis.empty()) {
            out << "\n// APIs referenced:\n";
            for (auto& a : usedApis) out << "//   " << a << "\n";
        }
        out << "\n";
    }

    std::string Emit(Function& func, XrefDB& xref, const TypeRecovery& types) {
        std::stringstream ss;
        ss << "uint64_t " << func.name << "(void) {\n";
        ss << "uint64_t " << func.name
            << "(uint64_t _a1, uint64_t _a2, uint64_t _a3, uint64_t _a4) {\n"
            << "    rcx.q = _a1; rdx.q = _a2; r8.q = _a3; r9.q = _a4;\n";
        if (CanStructure(func)) {
            StructCtx ctx{ func, xref, types, ss };
            ctx.EmitRegion(0, -1, -1);
        }
        else {
            GotoCtx ctx{ func, xref, types, ss };
            ctx.EmitAll();
        }
        ss << "    return rax.q;\n}\n\n";
        return ss.str();
    }

private:
    static bool CanStructure(const Function& func) {
        for (auto& blk : func.blocks) {
            if (!blk.isLoopHeader) continue;
            std::set<int> body(blk.loopBody.begin(), blk.loopBody.end());
            int outerPreds = 0;
            for (int p : blk.predecessors) if (!body.count(p)) outerPreds++;
            if (outerPreds > 1) return false;
        }
        return true;
    }

    static std::string CondOf(const std::string& m) {
        if (m == "jz" || m == "je")   return "zflag";
        if (m == "jnz" || m == "jne") return "!zflag";
        if (m == "jl" || m == "jb")   return "sflag";
        if (m == "jg" || m == "ja")   return "(!zflag && !sflag)";
        if (m == "jle" || m == "jbe") return "(zflag || sflag)";
        if (m == "jge" || m == "jae") return "!sflag";
        if (m == "js")                return "sflag";
        if (m == "jns")               return "!sflag";
        return "zflag";
    }

    // ---- 结构化上下文 ----
    struct StructCtx {
        const Function& func;
        XrefDB& xref;
        const TypeRecovery& types;
        std::ostream& out;
        std::set<int> emitted;

        StructCtx(const Function& f, XrefDB& x, const TypeRecovery& t, std::ostream& o)
            : func(f), xref(x), types(t), out(o) {
        }

        void EmitRegion(int start, int stop, int loopHeader) {
            int cur = start;
            while (cur >= 0 && cur < (int)func.blocks.size() && cur != stop) {
                if (emitted.count(cur)) return;
                auto& blk = func.blocks[cur];
                if (blk.isLoopHeader && cur != loopHeader) {
                    EmitLoop(cur);
                    return;
                }
                emitted.insert(cur);
                EmitBody(blk, /*skipCtrl=*/true);
                if (blk.pcode.empty()) { cur++; continue; }
                auto& last = blk.pcode.back();
                if (last.op == "RET") { out << "    return rax.q;\n"; return; }
                if (last.op == "JMP") {
                    int tgt = FindBlock(last.jumpTarget);
                    if (tgt == loopHeader && loopHeader >= 0) { out << "    continue;\n"; return; }
                    if (tgt == stop) return;
                    if (tgt < 0) return;
                    cur = tgt;
                    continue;
                }
                if (last.op == "CJMP") {
                    EmitConditional(FindBlock(last.jumpTarget), cur + 1, stop, loopHeader, last.src1);
                    return;
                }
                cur++;
            }
        }

        void EmitLoop(int header) {
            auto& hblk = func.blocks[header];
            emitted.insert(header);
            std::set<int> bodySet(hblk.loopBody.begin(), hblk.loopBody.end());
            std::vector<int> exits;
            for (int b : hblk.loopBody)
                for (int s : func.blocks[b].successors)
                    if (!bodySet.count(s)) exits.push_back(s);
            std::sort(exits.begin(), exits.end());
            exits.erase(std::unique(exits.begin(), exits.end()), exits.end());

            bool isWhileCond = false;
            std::string cond;
            if (!hblk.pcode.empty() && hblk.pcode.back().op == "CJMP" && exits.size() == 1) {
                int jt = FindBlock(hblk.pcode.back().jumpTarget);
                int ft = header + 1;
                if (jt == exits[0]) { isWhileCond = true; cond = "!(" + CondOf(hblk.pcode.back().src1) + ")"; }
                else if (ft == exits[0]) { isWhileCond = true; cond = CondOf(hblk.pcode.back().src1); }
            }

            if (isWhileCond) {
                out << "    while (" << cond << ") {\n";
                EmitBody(hblk, true);
                for (int s : hblk.successors)
                    if (bodySet.count(s) && s != header && s != exits[0])
                        EmitRegion(s, -1, header);
                out << "    }\n";
            }
            else {
                out << "    while (1) {\n";
                EmitBody(hblk, true);
                if (!hblk.pcode.empty() && hblk.pcode.back().op == "CJMP") {
                    int jt = FindBlock(hblk.pcode.back().jumpTarget);
                    if (!exits.empty() && jt == exits[0])
                        out << "        if (!(" << CondOf(hblk.pcode.back().src1) << ")) break;\n";
                }
                for (int s : hblk.successors)
                    if (bodySet.count(s) && s != header)
                        EmitRegion(s, -1, header);
                out << "        break;\n    }\n";
            }
            if (!exits.empty()) EmitRegion(exits[0], -1, -1);
        }

        void EmitConditional(int trueTgt, int falseTgt, int stop, int loopHeader, const std::string& mnemonic) {
            std::string cond = CondOf(mnemonic);
            int join = FindJoin(trueTgt, falseTgt);
            if (join < 0 || join == stop) join = stop;
            bool thenEmpty = (trueTgt == join || trueTgt == stop);
            bool elseEmpty = (falseTgt == join || falseTgt == stop);
            if (thenEmpty && elseEmpty) {
                if (join >= 0 && join != stop) EmitRegion(join, stop, loopHeader);
                return;
            }
            if (thenEmpty) {
                out << "    if (!(" << cond << ")) {\n";
                EmitRegion(falseTgt, join, loopHeader);
                out << "    }\n";
            }
            else if (elseEmpty) {
                out << "    if (" << cond << ") {\n";
                EmitRegion(trueTgt, join, loopHeader);
                out << "    }\n";
            }
            else {
                out << "    if (" << cond << ") {\n";
                EmitRegion(trueTgt, join, loopHeader);
                out << "    } else {\n";
                EmitRegion(falseTgt, join, loopHeader);
                out << "    }\n";
            }
            if (join >= 0 && join != stop) EmitRegion(join, stop, loopHeader);
        }

        void EmitBody(const BasicBlock& blk, bool skipCtrl) {
            for (size_t i = 0; i < blk.pcode.size(); ++i) {
                auto& s = blk.pcode[i];
                if (skipCtrl && i + 1 == blk.pcode.size() &&
                    (s.op == "JMP" || s.op == "CJMP" || s.op == "RET")) break;
                EmitOneStmt(s, out, xref, types);
            }
        }

        int FindBlock(uint64_t addr) const {
            for (auto& b : func.blocks) if (b.startAddr == addr) return b.id;
            return -1;
        }
        int FindJoin(int a, int b) const {
            if (a < 0 || b < 0) return -1;
            std::set<int> pa;
            int x = a;
            while (x >= 0) { pa.insert(x); int id = func.blocks[x].idom; if (id == x || id < 0) break; x = id; }
            int y = b;
            while (y >= 0) { if (pa.count(y)) return y; int id = func.blocks[y].idom; if (id == y || id < 0) break; y = id; }
            return -1;
        }
    };

    // ---- Goto 兜底上下文 ----
    struct GotoCtx {
        const Function& func;
        XrefDB& xref;
        const TypeRecovery& types;
        std::ostream& out;
        GotoCtx(const Function& f, XrefDB& x, const TypeRecovery& t, std::ostream& o)
            : func(f), xref(x), types(t), out(o) {
        }
        void EmitAll() {
            std::set<uint64_t> labels;
            for (auto& b : func.blocks) labels.insert(b.startAddr);
            for (auto& blk : func.blocks) {
                out << "L" << XrefDB::Hex(blk.startAddr) << ": ;\n";
                for (auto& s : blk.pcode) EmitOneStmt(s, out, xref, types);
                if (blk.pcode.empty()) continue;
                auto& last = blk.pcode.back();
                if (last.op == "RET") out << "    return rax.q;\n";
                else if (last.op == "JMP" && last.jumpTarget)
                else if (last.op == "JMP" && last.jumpTarget) {
                    if (labels.count(last.jumpTarget))
                        out << "    goto L" << XrefDB::Hex(last.jumpTarget) << ";\n";
                else if (last.op == "CJMP" && last.jumpTarget)
                }
                else if (last.op == "CJMP" && last.jumpTarget) {
                    if (labels.count(last.jumpTarget))
                        out << "    if (" << CondOf(last.src1) << ") goto L"
                            << XrefDB::Hex(last.jumpTarget) << ";\n";
                }
            }
        }
    };

public:
    static void EmitOneStmt(const PCodeStmt& s, std::ostream& out,
        XrefDB& xref, const TypeRecovery& types) {
        auto Opnd = [](const std::string& x) -> std::string {
            if (x.empty()) return "0";
            if (x.size() > 2 && x[0] == '0' && (x[1] == 'x' || x[1] == 'X')) return x + "ULL";
            if (x.compare(0, 4, "MEM(") == 0) return "MEM(" + x.substr(4);
            if (x.compare(0, 4, "STR_") == 0) return "0";
            static const std::set<std::string> R = {
            static const std::set<std::string> R64 = {
                "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
                "r8","r9","r10","r11","r12","r13","r14","r15",
                "eax","ebx","ecx","edx","esi","edi","ebp","esp",
                "al","cl","dl","sil","dil","bl",
                "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
                "r8w","r9w","r8b","r9b","ax","bx","cx","dx","si","di","bp","sp" };
            if (R.count(x)) return x + ".q";
                "r8","r9","r10","r11","r12","r13","r14","r15" };
            if (R64.count(x)) return x + ".q";
            return x;
            };
        if (s.op == "MOV") {
            out << "    " << Opnd(s.dst) << " = " << Opnd(s.src1) << ";\n";
            std::string base; int32_t off;
            if (TypeRecovery::ParseMem(s.dst, base, off) && off != 0) {
                std::string c = types.CandidatesFor(off);
                if (!c.empty()) out << "    // [OFF 0x" << std::hex << off << std::dec << "] " << c << "\n";
            }
        }
        else if (s.op == "ALU") {
            std::string o = "+=";
            if (s.src1 == "sub") o = "-=";
            else if (s.src1 == "xor" || s.src1 == "pxor") o = "^=";
            else if (s.src1 == "and" || s.src1 == "pand") o = "&=";
            else if (s.src1 == "or" || s.src1 == "por")  o = "|=";
            if (s.src1 == "inc")
                out << "    " << Opnd(s.dst) << "++;\n";
            else if (s.src1 == "dec")
                out << "    " << Opnd(s.dst) << "--;\n";
            else if (s.src1 == "neg")
                out << "    " << Opnd(s.dst) << " = (uint64_t)(-(int64_t)" << Opnd(s.dst) << ");\n";
            else if (s.src1 == "not")
                out << "    " << Opnd(s.dst) << " = ~" << Opnd(s.dst) << ";\n";
            else if (s.src1 == "shl")
                out << "    " << Opnd(s.dst) << " <<= " << Opnd(s.src2) << ";\n";
            else if (s.src1 == "shr")
                out << "    " << Opnd(s.dst) << " >>= " << Opnd(s.src2) << ";\n";
            else if (s.src1 == "sar")
                out << "    " << Opnd(s.dst) << " = (uint64_t)((int64_t)" << Opnd(s.dst)
                    << " >> " << Opnd(s.src2) << ");\n";
            else
                out << "    " << Opnd(s.dst) << " " << o << " " << Opnd(s.src2) << ";\n";
        }
        else if (s.op == "CMP") out << "    zflag = (" << Opnd(s.dst) << " == " << Opnd(s.src1) << ");\n";
        else if (s.op == "CMP") {
            out << "    { uint64_t _cmp_l = " << Opnd(s.dst)
                << "; uint64_t _cmp_r = " << Opnd(s.src1)
                << "; zflag = (_cmp_l == _cmp_r);"
                << " sflag = ((int64_t)_cmp_l < (int64_t)_cmp_r); }\n";
        }
        else if (s.op == "TEST") {
            out << "    { uint64_t _test = (" << Opnd(s.dst) << " & "
                << Opnd(s.src1) << "); zflag = (_test == 0);"
                << " sflag = ((int64_t)_test < 0); }\n";
        }
        else if (s.op == "CALL") {
            if (s.src1.compare(0, 4, "api_") == 0) {
                std::string name = s.src1.substr(4);
                out << "    API_CALL(\"" << name << "\", rcx.q, rdx.q, r8.q, r9.q);\n";
                xref.Add({ s.addr, 0, Xref::CALL_API, name });
            }
            else if (s.src1.compare(0, 5, "func_") == 0) {
                out << "    rax.q = " << s.src1 << "();\n";
                xref.Add({ s.addr, strtoull(s.src1.c_str() + 5, nullptr, 16), Xref::CALL_FUNC, s.src1 });
            else if (s.src2 == "DIRECT_FUNC" || s.src1.compare(0, 5, "func_") == 0) {
                out << "    rax.q = " << s.src1
                    << "(rcx.q, rdx.q, r8.q, r9.q);\n";
                uint64_t target = s.src1.compare(0, 5, "func_") == 0
                    ? strtoull(s.src1.c_str() + 5, nullptr, 16) : 0;
                xref.Add({ s.addr, target, Xref::CALL_FUNC, s.src1 });
            }
            else out << "    // [INDIRECT CALL] " << s.src1 << "\n";
            else {
                out << "    rax.q = CallIndirect((uint64_t)(" << s.src1
                    << "), rcx.q, rdx.q, r8.q, r9.q);\n";
                xref.Add({ s.addr, 0, Xref::CALL_FUNC, "indirect" });
            }
        }
        else if (s.op == "LEA") out << "    " << Opnd(s.dst) << " = " << Opnd(s.src1) << ";\n";
        else if (s.op == "PUSH")  out << "    // push " << s.src1 << "\n";
        else if (s.op == "POP")   out << "    // pop " << s.dst << "\n";
        else if (s.op == "SETCC") out << "    // setcc " << s.dst << "\n";
        else if (s.op == "CMOV")  out << "    // cmov " << s.dst << "\n";
        else if (s.op == "BIT_TEST") out << "    // bit_test\n";
        else if (s.op == "SIGN_EXT") out << "    // sign_ext\n";
        else if (s.op == "SIMD_MOV") out << "    // simd_mov\n";
        else if (s.op == "NOP")   out << "    // nop\n";
    }
};

// =====================================================================
// 终极反编译引擎
// =====================================================================
class UltimateDecompiler {
public:
    enum class EmitMode { Analysis, Compilable };
    UltimateDecompiler(ApiResolver* r) : m_apiResolver(r) {}
    void SetEmitMode(EmitMode m) { m_emitMode = m; }

    void LoadStrings(const uint8_t* fileData, size_t fileSize, const IMAGE_NT_HEADERS* nt, uint64_t imageBase) {
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            std::string sn(reinterpret_cast<const char*>(sec[i].Name),
                strnlen(reinterpret_cast<const char*>(sec[i].Name), 8));
            if (sn != ".rdata" && sn != ".data") continue;
            const uint8_t* d = fileData + sec[i].PointerToRawData;
            uint64_t va = imageBase + sec[i].VirtualAddress;
            std::string cur; uint64_t start = 0;
            for (uint32_t j = 0; j < sec[i].SizeOfRawData; ++j) {
                char c = (char)d[j];
                if (c >= 32 && c <= 126) { if (cur.empty()) start = va + j; cur += c; }
                else if (c == 0) { if (cur.length() >= 2) m_strings[start] = cur; cur.clear(); }
                else cur.clear();
            }
        }
    }

    void AnalyzeAllFunctions(std::vector<Insn>& allInsns, uint64_t imageBase, uint64_t entryVA) {
        m_imageBase = imageBase;
        FindFunctions(allInsns, entryVA);

        std::set<uint64_t> knownFunctions;
        for (auto& f : m_functions) knownFunctions.insert(f.startAddr);
        for (auto& f : m_functions) for (auto& b : f.blocks) for (auto& s : b.pcode) {
            if (s.op != "CALL" || s.src1.compare(0, 5, "func_") != 0) continue;
            uint64_t target = strtoull(s.src1.c_str() + 5, nullptr, 16);
            if (!knownFunctions.count(target)) s.src1 = "0";
        }
        RenameFunctions();

        unsigned int nT = std::thread::hardware_concurrency();
        if (!nT) nT = 4;
        std::atomic<size_t> idx(0);
        std::vector<std::thread> pool;
        for (unsigned int t = 0; t < nT; ++t) {
            pool.emplace_back([this, &idx]() {
                FunctionCFG cfg; DataFlow flow; DynamicApiResolver dyn;
                while (true) {
                    size_t i = idx.fetch_add(1);
                    if (i >= m_functions.size()) break;
                    Function& f = m_functions[i];
                    if (f.isDead) continue;
                    IdentifyLibraryCode(f);
                    if (f.isLibraryFunc) continue;
                    cfg.Build(f);
                    flow.Run(f);
                    dyn.Analyze(f, m_strings);
                }
            });
        }
        for (auto& t : pool) t.join();

        CompilableEmitter em;
        TypeRecovery types;
        for (auto& f : m_functions) {
            if (f.isDead) continue;
            if (f.isLibraryFunc) { f.generatedCode = EmitLibraryStub(f); continue; }
            if (m_emitMode == EmitMode::Compilable)
                f.generatedCode = em.Emit(f, m_xref, types);
            else
                f.generatedCode = EmitFunction(f);
        }
    }

    void WriteToFile(const std::string& path, std::vector<Insn>&) {
        std::ofstream out(path);
        if (!out.is_open()) { std::cerr << "[-] Cannot open: " << path << " errno=" << errno << "\n"; return; }

        std::set<std::string> usedApis;
        for (auto& f : m_functions) for (auto& b : f.blocks) for (auto& s : b.pcode)
            if (s.op == "CALL" && s.src1.compare(0, 4, "api_") == 0)
                usedApis.insert(s.src1.substr(4));

        if (m_emitMode == EmitMode::Compilable) {
            CompilableEmitter em;
            em.EmitPreamble(out, usedApis);
            for (auto& f : m_functions)
                if (!f.isDead && !f.isLibraryFunc)
                    out << "uint64_t " << f.name << "(void);\n";
                if (!f.isDead)
                    out << "uint64_t " << f.name
                        << "(uint64_t, uint64_t, uint64_t, uint64_t);\n";
            out << "\n";
            for (auto& f : m_functions)
                if (!f.isDead && !f.isLibraryFunc && !f.generatedCode.empty())
                if (!f.isDead && !f.generatedCode.empty())
                    out << f.generatedCode;
            out << "int main(void) {\n    entry_point();\n    return 0;\n}\n";
            out << "int main(int argc, char** argv) {\n"
                << "    entry_point((uint64_t)argc, (uint64_t)argv, 0, 0);\n"
                << "    return 0;\n}\n";
        }
        else {
            out << "\xEF\xBB\xBF#include <stdint.h>\n#include <windows.h>\n#include <string.h>\n\n";
            out << "uint64_t rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8,r9,r10,r11,r12,r13,r14,r15;\n";
            out << "uint8_t memory[0x100000];\n#define MEM(a) memory[(uint32_t)(a) & 0xFFFFF]\n\n";
            if (!usedApis.empty()) {
                out << "// --- API Mapping ---\n";
                for (auto& a : usedApis) out << "#define api_" << a << " " << a << "\n";
                out << "\n";
            }
            bool printed = false;
            for (auto& f : m_functions)
                if (!f.isDead && !f.generatedCode.empty()) {
                    out << f.generatedCode << "\n";
                    if (f.name == "entry_point") printed = true;
                }
            if (!printed) out << "void entry_point() { }\n\n";
            out << "int main() { entry_point(); return 0; }\n";
        }
    }

    static std::string SafeName(std::string name) {
        for (char& c : name) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_')) c = '_';
        }
        if (name.empty() || (name[0] >= '0' && name[0] <= '9')) name = "fn_" + name;
        return name;
    }

    void RenameFunctions() {
        std::unordered_map<std::string, std::string> oldToNew;
        std::unordered_map<std::string, int> nameUse;
        std::set<std::string> reserved{"entry_point"};
        for (auto& f : m_functions) {
            if (f.name == "entry_point") continue;
            std::map<std::string, int> apiCount;
            for (auto& b : f.blocks) for (auto& s : b.pcode)
                if (s.op == "CALL" && s.src1.rfind("api_", 0) == 0)
                    ++apiCount[s.src1.substr(4)];
            std::string base;
            if (!apiCount.empty()) {
                auto best = std::max_element(apiCount.begin(), apiCount.end(),
                    [](const auto& a, const auto& b) { return a.second < b.second; });
                base = SafeName(best->first) + "_wrapper";
            }
            if (base.empty()) base = "sub_" + ToHex(f.startAddr);
            std::string old = f.name;
            std::string candidate = base;
            if (++nameUse[base] > 1 || reserved.count(candidate))
                candidate = base + "_" + ToHex(f.startAddr);
            while (reserved.count(candidate)) candidate += "_fn";
            reserved.insert(candidate);
            oldToNew[old] = candidate;
            f.name = candidate;
        }
        for (auto& f : m_functions) for (auto& b : f.blocks) for (auto& s : b.pcode) {
            if (s.op != "CALL" || s.src1.compare(0, 5, "func_") != 0) continue;
            auto it = oldToNew.find(s.src1);
            if (it != oldToNew.end()) {
                s.src1 = it->second;
                s.src2 = "DIRECT_FUNC";
            }
        }
    }

private:
    uint64_t m_imageBase = 0;
    ApiResolver* m_apiResolver;
    EmitMode m_emitMode = EmitMode::Compilable;
    std::vector<Function> m_functions;
    std::unordered_map<uint64_t, std::string> m_strings;
    std::set<uint64_t> m_calledFuncs;
    XrefDB m_xref;

    static uint64_t ImmediateTarget(const Insn& insn, const ZydisDecodedOperand& op) {
        if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return 0;
        if (op.imm.is_relative)
            return insn.addr + insn.instr.length + static_cast<int64_t>(op.imm.value.s);
        return op.imm.value.u;
    }

    std::string ToHex(uint64_t v) { std::stringstream ss; ss << std::hex << v; return ss.str(); }

    std::string GetRegName(ZydisRegister reg) {
        const char* name = ZydisRegisterGetString(reg);
        if (!name) return "unknown";
        std::string s(name);
        if (s == "ecx") return "rcx"; if (s == "edx") return "rdx";
        if (s == "r8d") return "r8";  if (s == "r9d") return "r9";
        if (s == "eax") return "rax"; if (s == "ebx") return "rbx";
        if (s.find("xmm") != std::string::npos) return s;
        return s;
    }

    void IdentifyLibraryCode(Function& f) {
        if (f.name == "entry_point") return;
        bool sec = false, rtl = false, tim = false;
        for (auto& b : f.blocks) for (auto& s : b.pcode) {
            if (s.op == "CALL") {
                if (s.src1.find("GetSystemTimeAsFileTime") != std::string::npos) tim = true;
                if (s.src1.find("RtlCaptureContext") != std::string::npos) rtl = true;
            }
            if (s.src1.find("0x2b992ddfa232") != std::string::npos) sec = true;
        }
        if (sec && tim) { f.isLibraryFunc = true; f.libFuncName = "__security_init_cookie"; }
        else if (rtl) { f.isLibraryFunc = true; f.libFuncName = "__SEH_Exception_Handler"; }
    }

    std::string EmitLibraryStub(const Function& f) {
        std::stringstream ss;
        ss << "uint64_t " << f.name << "(void) {\n    // [FLIRT] " << f.libFuncName << "\n    return 0;\n}\n\n";
        ss << "uint64_t " << f.name
           << "(uint64_t _a1, uint64_t _a2, uint64_t _a3, uint64_t _a4) {\n    // [FLIRT] "
           << f.libFuncName << "\n    return 0;\n}\n\n";
        return ss.str();
    }

    void FindFunctions(std::vector<Insn>& allInsns, uint64_t entryVA) {
        std::set<uint64_t> starts;
        std::set<uint64_t> instructionAddresses;
        for (auto& insn : allInsns) instructionAddresses.insert(insn.addr);
        uint64_t actualEntry = entryVA;
        bool found = false;
        if (!allInsns.empty()) {
            if (entryVA) for (auto& i : allInsns) if (i.addr == entryVA) { found = true; break; }
            if (!found) actualEntry = allInsns.front().addr;
            starts.insert(actualEntry);
        }
        for (auto& i : allInsns)
            if (ZydisMnemonicGetString(i.instr.mnemonic) == std::string("call") &&
                i.instr.operand_count > 0 && i.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                starts.insert(i.operands[0].imm.value.u);
                m_calledFuncs.insert(i.operands[0].imm.value.u);
                uint64_t target = ImmediateTarget(i, i.operands[0]);
                if (instructionAddresses.count(target)) {
                    starts.insert(target);
                    m_calledFuncs.insert(target);
                }
            }
        size_t i = 0;
        bool assigned = false;
        while (i < allInsns.size()) {
            Function f;
            f.startAddr = allInsns[i].addr;
            if (f.startAddr == actualEntry && !assigned) { f.name = "entry_point"; f.isDead = false; assigned = true; }
            else f.name = "func_" + ToHex(f.startAddr);
            f.blocks.push_back({});
            while (i < allInsns.size()) {
                if (i > 0 && starts.count(allInsns[i].addr) && allInsns[i].addr != f.startAddr) break;
                Insn& insn = allInsns[i];
                std::string m = ZydisMnemonicGetString(insn.instr.mnemonic);
                if (m == "int3" || m == "nop" || m == "endbr64" || m == "invalid") { i++; continue; }
                // FIX-1: 0x00 填充过滤
                if (m == "add" && insn.instr.operand_count == 2 &&
                    insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && insn.operands[0].size == 8 &&
                    insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    insn.operands[1].reg.value == ZYDIS_REGISTER_AL) {
                    i++; continue;
                }

                if (m == "call" || m == "add" || m == "sub" || m == "xor" ||
                    m.rfind("j", 0) == 0 || m == "ret") f.isDead = false;

                PCodeStmt s; s.addr = insn.addr; s.op = "UNK";
                auto GetOp = [&](int idx) -> std::string {
                    if (idx >= insn.instr.operand_count) return "";
                    auto& op = insn.operands[idx];
                    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) return GetRegName(op.reg.value);
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) return "0x" + ToHex(op.imm.value.u);
                    if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        std::string r = "MEM(";
                        if (op.mem.base != ZYDIS_REGISTER_NONE) r += GetRegName(op.mem.base);
                        if (op.mem.disp.value != 0)
                            r += (op.mem.disp.value > 0 ? "+" : "") + std::to_string(op.mem.disp.value);
                        if (op.mem.base == ZYDIS_REGISTER_RIP) {
                            uint64_t target = insn.addr + insn.instr.length + op.mem.disp.value;
                            r += "0x" + ToHex(target);
                        }
                        else if (op.mem.base != ZYDIS_REGISTER_NONE) r += GetRegName(op.mem.base) + ".q";
                        if (op.mem.index != ZYDIS_REGISTER_NONE) {
                            if (op.mem.base != ZYDIS_REGISTER_NONE && op.mem.base != ZYDIS_REGISTER_RIP) r += "+";
                            r += GetRegName(op.mem.index) + ".q";
                            if (op.mem.scale > 1) r += "*" + std::to_string(op.mem.scale);
                        }
                        if (op.mem.disp.value != 0 && op.mem.base != ZYDIS_REGISTER_RIP)
                            r += (op.mem.base != ZYDIS_REGISTER_NONE || op.mem.index != ZYDIS_REGISTER_NONE)
                                ? (op.mem.disp.value > 0 ? "+" : "") + std::to_string(op.mem.disp.value)
                                : std::to_string(op.mem.disp.value);
                        r += ")";
                        return r;
                    }
                    return "unknown";
                    };

                if (m == "mov" || m == "movzx" || m == "movsxd" || m == "movsx") {
                    s.op = "MOV"; s.dst = GetOp(0); s.src1 = GetOp(1);
                }
                else if (m.find("movdqa") != std::string::npos || m.find("movdqu") != std::string::npos || m.find("movups") != std::string::npos) {
                    s.op = "SIMD_MOV"; s.dst = GetOp(0); s.src1 = GetOp(1);
                }
                else if (m == "lea") {
                    s.op = "LEA"; s.dst = GetOp(0);
                    if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        insn.operands[1].mem.base == ZYDIS_REGISTER_RIP) {
                        uint64_t tgt = insn.addr + insn.instr.length + insn.operands[1].mem.disp.value;
                        s.src1 = "STR_" + ToHex(tgt);
                    }
                    else s.src1 = GetOp(1);
                }
                else if (m == "add" || m == "sub" || m == "xor" || m == "and" || m == "or" ||
                    m == "shl" || m == "shr" || m == "sar" || m == "pxor" || m == "pand" || m == "por") {
                    s.op = "ALU"; s.dst = GetOp(0); s.src1 = m; s.src2 = GetOp(1);
                }
                else if (m == "inc" || m == "dec" || m == "neg" || m == "not") {
                    s.op = "ALU"; s.dst = GetOp(0); s.src1 = m; s.src2 = "1";
                }
                else if (m == "bt" || m == "bts" || m == "btr" || m == "btc") {
                    s.op = "BIT_TEST"; s.dst = GetOp(0); s.src1 = GetOp(1); s.src2 = m;
                }
                else if (m == "cdqe" || m == "cdq" || m == "cwd" || m == "cqo") {
                    s.op = "SIGN_EXT"; s.dst = "rax"; s.src1 = m;
                }
                else if (m == "cmp") { s.op = "CMP"; s.dst = GetOp(0); s.src1 = GetOp(1); }
                else if (m == "test") { s.op = "CMP"; s.dst = GetOp(0); s.src1 = "0"; }
                else if (m == "test") { s.op = "TEST"; s.dst = GetOp(0); s.src1 = GetOp(1); }
                else if (m == "cmovz" || m == "cmove" || m == "cmovnz" || m == "cmovne" || m == "cmovl" || m == "cmovg") {
                    s.op = "CMOV"; s.dst = GetOp(0); s.src1 = GetOp(1); s.src2 = m;
                }
                else if (m == "setz" || m == "sete" || m == "setnz" || m == "setne" || m == "setl" || m == "setg") {
                    s.op = "SETCC"; s.dst = GetOp(0); s.src1 = m;
                }
                else if (m == "call") {
                    s.op = "CALL";
                    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        s.src1 = "func_" + ToHex(insn.operands[0].imm.value.u);
                    else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        insn.operands[0].mem.base == ZYDIS_REGISTER_RIP) {
                        uint64_t tgt = insn.addr + insn.instr.length + insn.operands[0].mem.disp.value;
                        std::string api = m_apiResolver->GetApiName(tgt);
                        if (!api.empty()) s.src1 = "api_" + api;
                        else s.src1 = "((void(*)())MEM(0x" + ToHex(tgt) + "))";
                    }
                    else s.src1 = GetOp(0);
                }
                else if (m == "jmp") {
                    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        insn.operands[0].mem.base == ZYDIS_REGISTER_RIP) {
                        uint64_t tgt = insn.addr + insn.instr.length + insn.operands[0].mem.disp.value;
                        std::string api = m_apiResolver->GetApiName(tgt);
                        if (!api.empty()) {
                            s.op = "CALL"; s.src1 = "api_" + api;
                            f.blocks.back().pcode.push_back(s);
                            i++; break;
                        }
                    }
                    s.op = "JMP";
                    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        s.jumpTarget = insn.operands[0].imm.value.u;
                        s.jumpTarget = ImmediateTarget(insn, insn.operands[0]);
                }
                else if (m.rfind("j", 0) == 0) {
                    s.op = "CJMP"; s.src1 = m;
                    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        s.jumpTarget = insn.operands[0].imm.value.u;
                        s.jumpTarget = ImmediateTarget(insn, insn.operands[0]);
                }
                else if (m == "ret") s.op = "RET";
                else if (m == "push") { s.op = "PUSH"; s.src1 = GetOp(0); }
                else if (m == "pop") { s.op = "POP"; s.dst = GetOp(0); }

                if (s.op != "UNK") f.blocks.back().pcode.push_back(s);
                if (s.op == "UNK") s.op = "UNKNOWN";
                f.blocks.back().pcode.push_back(s);
                i++;
                if (m == "ret") break;
            }
            if (f.name == "entry_point" && f.blocks[0].pcode.empty()) {
                PCodeStmt d; d.op = "NOP"; d.addr = f.startAddr;
                f.blocks[0].pcode.push_back(d);
            }
            m_functions.push_back(f);
        }
    }

    // Analysis 模式（伪代码输出，阅读用）
    std::string EmitFunction(const Function& func) {
        std::stringstream ss;
        ss << "void " << func.name << "() {\n";
        std::set<uint64_t> jumps;
        for (auto& b : func.blocks) for (auto& s : b.pcode)
            if (s.op == "JMP" || s.op == "CJMP") jumps.insert(s.jumpTarget);

        bool hasCode = false;
        std::string lastLine; int dup = 0;
        auto Emit = [&](const std::string& l) {
            if (l == lastLine) { ++dup; if (dup >= 3) return; }
            else { dup = 0; lastLine = l; }
            ss << l;
            };

        std::map<std::string, std::string> rc;
        for (auto& b : func.blocks) {
            if (b.isLoopHeader) ss << "    while (1) {\n";
            for (auto& s : b.pcode) {
                if (s.op == "ALU" && s.src1 == "add" &&
                    (s.src2 == "al" || s.src2 == "eax" || s.src2 == "rax") &&
                    s.dst.find("MEM(") == 0) continue;
                if (s.op == "ALU" && s.dst == "rsp" && (s.src1 == "add" || s.src1 == "sub")) continue;
                if (s.op == "MOV" && s.dst.find("r") == 0) { rc[s.dst] = s.src1; continue; }
                if (s.op == "LEA" && s.dst.find("r") == 0) {
                    if (s.src1.find("STR_") == 0) {
                        uint64_t a = std::stoull(s.src1.substr(4), nullptr, 16);
                        auto it = m_strings.find(a);
                        if (it != m_strings.end()) rc[s.dst] = "\"" + it->second + "\"";
                        else rc[s.dst] = "(uint64_t)&MEM(" + ToHex(a - m_imageBase) + ")";
                    }
                    else rc[s.dst] = "(uint64_t)&" + s.src1;
                    continue;
                }
                if (s.op == "ALU" && s.src1 == "xor" && s.dst == s.src2) { rc[s.dst] = "0"; continue; }

                if (s.op == "MOV") { Emit("    " + s.dst + " = " + s.src1 + ";\n"); hasCode = true; }
                if (s.op == "MOV") {
                    std::string lhs = s.dst;
                    if (lhs.find("MEM(") == 0) lhs = "MEM" + lhs.substr(3);
                    Emit("    " + lhs + " = " + s.src1 + ";\n");
                    hasCode = true;
                }
                else if (s.op == "ALU") {
                    if (s.src1 == "inc") Emit("    " + s.dst + "++;\n");
                    else if (s.src1 == "dec") Emit("    " + s.dst + "--;\n");
                    else {
                        std::string o = "+";
                        if (s.src1 == "sub") o = "-";
                        else if (s.src1 == "xor" || s.src1 == "pxor") o = "^";
                        else if (s.src1 == "and") o = "&";
                        else if (s.src1 == "or") o = "|";
                        else if (s.src1 == "and" || s.src1 == "pand") o = "&";
                        else if (s.src1 == "or" || s.src1 == "por") o = "|";
                        Emit("    " + s.dst + " " + o + "= " + s.src2 + ";\n");
                    }
                    hasCode = true;
                }
                else if (s.op == "CMP") { hasCode = true; }
                else if (s.op == "CALL") {
                    if (s.src1.rfind("api_", 0) == 0) {
                        Emit("    rax.q = ResolveApi(\"" + s.src1.substr(4) + "\");\n");
                    } else {
                        std::string a1 = rc.count("rcx") ? rc["rcx"] : "0";
                        std::string a2 = rc.count("rdx") ? rc["rdx"] : "0";
                        std::string a3 = rc.count("r8") ? rc["r8"] : "0";
                        std::string a4 = rc.count("r9") ? rc["r9"] : "0";
                        Emit("    " + s.src1 + "(" + a1 + ", " + a2 + ", " + a3 + ", " + a4 + ");\n");
                    }
                    hasCode = true; rc.clear();
                }
                else if (s.op == "RET") { Emit("    return;\n"); hasCode = true; }
                else if (s.op == "JMP" || s.op == "CJMP" || s.op == "PUSH" ||
                    s.op == "POP" || s.op == "NOP" || s.op == "LEA") {
                    hasCode = true;
                }
            }
            if (b.isLoopHeader) ss << "    }\n";
        }
        if (!hasCode) ss << "    // [WARNING] no valid decoded instructions.\n";
        for (uint64_t l : jumps) ss << "label_0x" << ToHex(l) << ": ;\n";
        ss << "}\n\n";
        return ss.str();
    }
};

// =====================================================================
// 主程序
// =====================================================================
int main(int argc, char* argv[]) {
    std::cout << "--- Disasm Engine Started ---\n";
    std::string in, out, emit = "compilable";
    auto printHelp = []() {
        std::cout
            << "Usage:\n"
            << "  Disasm -f <input.exe> -c <output.c> [--emit analysis|compilable]\n\n"
            << "Options:\n"
            << "  -f <file>       Input PE/EXE file\n"
            << "  -c <file>       Generated C output file\n"
            << "  --emit <mode>   analysis or compilable (default: compilable)\n"
            << "  -h, -help, --help\n"
            << "                  Show this help message\n";
    };
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-f" && i + 1 < argc) in = argv[++i];
        if (a == "-h" || a == "-help" || a == "--help" || a == "-hlep") {
            printHelp();
            return 0;
        }
        else if (a == "-f" && i + 1 < argc) in = argv[++i];
        else if (a == "-c" && i + 1 < argc) out = argv[++i];
        else if (a == "--emit" && i + 1 < argc) emit = argv[++i];
    }
    if (in.empty() || out.empty()) {
        std::cerr << "Usage: Disasm -f <in.exe> -c <out.c> [--emit analysis|compilable]\n";
        printHelp();
        return 1;
    }

    std::ifstream file(in, std::ios::binary | std::ios::ate);
    if (!file) { std::cerr << "[-] Cannot open: " << in << " errno=" << errno << "\n"; return 1; }
    std::streamsize sz = file.tellg();
    if (sz <= 0) { std::cerr << "[-] Empty file.\n"; return 1; }
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> fd((size_t)sz);
    file.read(reinterpret_cast<char*>(fd.data()), sz);
    file.close();

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(fd.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { std::cerr << "[-] Not PE.\n"; return 1; }
    const uint8_t* ntBase = fd.data() + dos->e_lfanew;
    const auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + 4);
    uint16_t magic = *reinterpret_cast<const uint16_t*>(ntBase + 4 + sizeof(IMAGE_FILE_HEADER));
    bool is64 = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    uint64_t imageBase, entry;
    if (is64) {
        const auto* o = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(ntBase + 4 + sizeof(IMAGE_FILE_HEADER));
        imageBase = o->ImageBase; entry = imageBase + o->AddressOfEntryPoint;
    }
    else {
        const auto* o = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(ntBase + 4 + sizeof(IMAGE_FILE_HEADER));
        imageBase = o->ImageBase; entry = imageBase + o->AddressOfEntryPoint;
    }

    ApiResolver resolver;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(ntBase);
    resolver.LoadImports(fd.data(), sz, nt, imageBase);

    const auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        ntBase + 4 + sizeof(IMAGE_FILE_HEADER) + fh->SizeOfOptionalHeader);
    const IMAGE_SECTION_HEADER* target = nullptr;
    for (int i = 0; i < fh->NumberOfSections; ++i) {
        if (sec[i].SizeOfRawData > 0 && strncmp((const char*)sec[i].Name, ".text", 5) == 0) { target = &sec[i]; break; }
    }
    if (!target) for (int i = 0; i < fh->NumberOfSections; ++i)
        if (sec[i].SizeOfRawData > 0 && (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) { target = &sec[i]; break; }
    if (!target) { std::cerr << "[-] No executable section.\n"; return 1; }

    const uint8_t* code = fd.data() + target->PointerToRawData;
    uint32_t codeSz = target->SizeOfRawData;
    uint64_t vbase = imageBase + target->VirtualAddress;

    ZydisDecoder dec;
    if (is64) ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    else ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    std::vector<Insn> all;
    ZyanUSize off = 0;
    while (off < codeSz) {
        Insn ins;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, codeSz - off, &ins.instr, ins.operands))) {
            ins.addr = vbase + off;
            all.push_back(ins);
            off += ins.instr.length;
        }
        else off += 1;
    }
    std::cout << "[+] Disassembled " << all.size() << " instructions.\n";

    UltimateDecompiler decomp(&resolver);
    decomp.SetEmitMode(emit == "analysis" ? UltimateDecompiler::EmitMode::Analysis
        : UltimateDecompiler::EmitMode::Compilable);
    decomp.LoadStrings(fd.data(), sz, nt, imageBase);
    decomp.AnalyzeAllFunctions(all, imageBase, entry);
    decomp.WriteToFile(out, all);
    std::cout << "[SUCCESS] Output: " << out << "\n";
    return 0;
}
