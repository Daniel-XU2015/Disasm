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
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>
#include <unordered_map>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>

#include "Zydis.h"

// =========================================================
// API 签名与环境
// =========================================================
struct ApiParam { std::string type; bool isString; ApiParam(std::string t, bool s) : type(t), isString(s) {} };
struct ApiSignature { std::string name; std::vector<ApiParam> params; };

class ApiDatabase {
public:
    ApiDatabase() { Add("MessageBoxA", { {"HWND", false}, {"LPCSTR", true}, {"LPCSTR", true}, {"UINT", false} }); }
    bool GetSignature(const std::string& name, ApiSignature& outSig) {
        if (m_db.count(name)) { outSig = m_db[name]; return true; }
        return false;
    }
private:
    std::unordered_map<std::string, ApiSignature> m_db;
    void Add(const std::string& name, std::vector<ApiParam> params) { m_db[name] = { name, params }; }
};

class ApiResolver {
public:
    void LoadImports(const uint8_t* fileData, size_t fileSize, const IMAGE_NT_HEADERS* ntHeader, uint64_t imageBase) {
        uint32_t importRva = 0;
        if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            importRva = reinterpret_cast<const IMAGE_NT_HEADERS32*>(ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        } else {
            importRva = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        }
        if (importRva == 0) return;

        const auto* importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            RvaToFileOffset(fileData, fileSize, ntHeader, importRva));
        if (!importDesc) return;

        while (importDesc->Name != 0) {
            const auto* thunkData = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
                RvaToFileOffset(fileData, fileSize, ntHeader, importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
            uint64_t iatAddress = imageBase + importDesc->FirstThunk;

            while (thunkData && thunkData->u1.AddressOfData != 0) {
                if (!(thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                    const auto* importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        RvaToFileOffset(fileData, fileSize, ntHeader, thunkData->u1.AddressOfData));
                    if (importByName) m_iatMap[iatAddress] = std::string(importByName->Name);
                }
                iatAddress += (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 4 : 8;
                thunkData++;
            }
            importDesc++;
        }
    }
    std::string GetApiName(uint64_t address) {
        auto it = m_iatMap.find(address);
        return it != m_iatMap.end() ? it->second : "";
    }
private:
    std::unordered_map<uint64_t, std::string> m_iatMap;
    const uint8_t* RvaToFileOffset(const uint8_t* fileData, size_t fileSize, const IMAGE_NT_HEADERS* ntHeader, uint32_t rva) {
        const auto* section = IMAGE_FIRST_SECTION(ntHeader);
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
            if (rva >= section[i].VirtualAddress && rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
                uint32_t offset = rva - section[i].VirtualAddress + section[i].PointerToRawData;
                if (offset < fileSize) return fileData + offset;
            }
        }
        return nullptr;
    }
};

// =========================================================
// 数据结构：P-Code
// =========================================================
struct Insn {
    uint64_t addr;
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
};

struct PCodeStmt {
    std::string op;       
    std::string dst;      
    std::string src1;     
    std::string src2;     
    uint64_t jumpTarget;  
    uint64_t addr;        
};

struct BasicBlock {
    int id;
    uint64_t startAddr;
    std::vector<PCodeStmt> pcode;
    std::vector<int> successors;
    std::vector<int> predecessors;
    int idom = -1;
    bool isLoopHeader = false;
};

struct Function {
    uint64_t startAddr;
    std::string name;
    std::vector<BasicBlock> blocks;
    bool isDead = true;
    bool isLibraryFunc = false;
    std::string libFuncName;
    std::string generatedCode;
};

// =========================================================
// 终极反编译引擎
// =========================================================
class UltimateDecompiler {
public:
    UltimateDecompiler(ApiResolver* resolver) : m_apiResolver(resolver) {}

    void LoadStrings(const uint8_t* fileData, size_t fileSize, const IMAGE_NT_HEADERS* ntHeader, uint64_t imageBase) {
        const auto* section = IMAGE_FIRST_SECTION(ntHeader);
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
            std::string secName(reinterpret_cast<const char*>(section[i].Name), strnlen(reinterpret_cast<const char*>(section[i].Name), 8));
            if (secName == ".rdata" || secName == ".data") {
                const uint8_t* data = fileData + section[i].PointerToRawData;
                uint32_t size = section[i].SizeOfRawData;
                uint64_t va = imageBase + section[i].VirtualAddress;
                std::string currentStr; uint64_t currentStart = 0;
                for (uint32_t j = 0; j < size; ++j) {
                    char c = (char)data[j];
                    if (c >= 32 && c <= 126) {
                        if (currentStr.empty()) currentStart = va + j;
                        currentStr += c;
                    } else if (c == 0) {
                        if (currentStr.length() >= 1) m_strings[currentStart] = currentStr;
                        currentStr.clear();
                    } else currentStr.clear();
                }
            }
        }
    }

    void AnalyzeAllFunctions(std::vector<Insn>& allInstructions, uint64_t imageBase, uint64_t peEntryPointVA) {
        m_imageBase = imageBase;
        FindFunctions(allInstructions, peEntryPointVA);
        
        unsigned int numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;
        std::atomic<size_t> currentIndex(0);
        std::vector<std::thread> threads;

        for (unsigned int t = 0; t < numThreads; ++t) {
            threads.emplace_back([this, &currentIndex]() {
                while (true) {
                    size_t idx = currentIndex.fetch_add(1);
                    if (idx >= m_functions.size()) break;
                    Function& func = m_functions[idx];
                    if (func.isDead) continue;
                    
                    IdentifyLibraryCode(func);
                    if (func.isLibraryFunc) {
                        func.generatedCode = EmitLibraryStub(func);
                        continue;
                    }
                    
                    BuildCFG(func);
                    BuildDominatorTree(func);
                    FindLoops(func);
                    func.generatedCode = EmitFunction(func);
                }
            });
        }
        for (auto& th : threads) th.join();
    }

    void WriteToFile(const std::string& outPath, std::vector<Insn>& allInstructions) {
        std::ofstream out(outPath);
        out << "\xEF\xBB\xBF#include <stdint.h>\n#include <windows.h>\n\n";
        out << "uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15;\n";
        out << "uint8_t memory[0x100000];\n#define MEM(a) memory[(uint32_t)(a) & 0xFFFFF]\n\n";

        std::set<std::string> usedApis;
        bool printedEntry = false;

        for (const auto& func : m_functions) {
            if (!func.isDead) {
                std::string code = func.generatedCode;
                size_t pos = 0;
                while ((pos = code.find("api_", pos)) != std::string::npos) {
                    size_t end = pos + 4;
                    while (end < code.length() && (isalnum((unsigned char)code[end]) || code[end] == '_')) end++;
                    usedApis.insert(code.substr(pos + 4, end - pos - 4));
                    pos = end;
                }
            }
        }

        if (!usedApis.empty()) {
            out << "// --- API Mapping ---\n";
            for (const auto& api : usedApis) out << "#define api_" << api << " " << api << "\n";
            out << "\n";
        }

        for (const auto& func : m_functions) {
            if (!func.isDead && !func.generatedCode.empty()) {
                out << func.generatedCode << "\n";
                if (func.name == "entry_point") printedEntry = true;
            }
        }

        if (!printedEntry) {
            out << "void entry_point(int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4) {\n";
            if (!allInstructions.empty()) {
                out << "    // [WARNING] Zydis failed to decode. Dumping raw instructions from the buffer.\n";
                int count = 0;
                for (auto& insn : allInstructions) {
                    char asmBuf[256];
                    ZydisFormatter formatter;
                    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
                    ZydisFormatterFormatInstruction(&formatter, &insn.instr, insn.operands, insn.instr.operand_count_visible, asmBuf, sizeof(asmBuf), insn.addr, ZYAN_NULL);
                    out << "    // 0x" << std::hex << insn.addr << ": " << asmBuf << "\n";
                    if (++count > 200) break;
                }
            } else {
                out << "    // [WARNING] The target file has no valid .text section or it's encrypted/packed.\n";
            }
            out << "}\n\n";
        }

        out << "int main() {\n    entry_point(0, 0, 0, 0);\n    return 0;\n}\n";
    }

private:
    uint64_t m_imageBase;
    ApiResolver* m_apiResolver;
    std::vector<Function> m_functions;
    std::unordered_map<uint64_t, std::string> m_strings;
    std::set<uint64_t> m_calledFuncs;

    void IdentifyLibraryCode(Function& func) {
        if (func.name == "entry_point") return; 
        
        bool hasSecurityCookie = false;
        bool hasRtlCapture = false;
        bool hasTimeCheck = false;
        bool hasRtlUnwind = false;
        bool hasCxxException = false;

        for (auto& block : func.blocks) {
            for (auto& stmt : block.pcode) {
                if (stmt.op == "CALL") {
                    if (stmt.src1.find("api_GetSystemTimeAsFileTime") != std::string::npos) hasTimeCheck = true;
                    if (stmt.src1.find("api_QueryPerformanceCounter") != std::string::npos) hasTimeCheck = true;
                    if (stmt.src1.find("api_RtlCaptureContext") != std::string::npos) hasRtlCapture = true;
                    if (stmt.src1.find("api_RtlUnwindEx") != std::string::npos) hasRtlUnwind = true;
                    if (stmt.src1.find("api_RaiseException") != std::string::npos) hasCxxException = true;
                }
                if (stmt.src1.find("0x2b992ddfa232") != std::string::npos) hasSecurityCookie = true;
            }
        }

        if (hasSecurityCookie && hasTimeCheck) {
            func.isLibraryFunc = true;
            func.libFuncName = "__security_init_cookie";
        } else if (hasRtlCapture || hasRtlUnwind) {
            func.isLibraryFunc = true;
            func.libFuncName = "__SEH_Exception_Handler";
        } else if (hasCxxException) {
            func.isLibraryFunc = true;
            func.libFuncName = "__CxxThrowException";
        } else if (func.blocks.size() == 1 && func.blocks[0].pcode.size() <= 2) {
            func.isLibraryFunc = true;
            func.libFuncName = "CRT_Stub";
        }
    }

    std::string EmitLibraryStub(const Function& func) {
        std::stringstream ss;
        ss << "void " << func.name << "(int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4) {\n";
        ss << "    // [FLIRT] Identified as: " << func.libFuncName << "\n";
        ss << "}\n\n";
        return ss.str();
    }

    std::string GetRegName(ZydisRegister reg) {
        const char* name = ZydisRegisterGetString(reg);
        if (!name) return "unknown";
        std::string s(name);
        if (s == "ecx") return "rcx"; if (s == "edx") return "rdx";
        if (s == "r8d") return "r8";  if (s == "r9d") return "r9";
        if (s == "eax") return "rax"; if (s == "ebx") return "rbx";
        return s;
    }

    void FindFunctions(std::vector<Insn>& allInstructions, uint64_t peEntryPointVA) {
        std::set<uint64_t> funcStarts;
        uint64_t actualEntryPointVA = peEntryPointVA;
        bool foundInText = false;
        
        if (!allInstructions.empty()) {
            if (peEntryPointVA != 0) {
                for (auto& insn : allInstructions) {
                    if (insn.addr == peEntryPointVA) { foundInText = true; break; }
                }
            }
            if (!foundInText) actualEntryPointVA = allInstructions.front().addr;
            funcStarts.insert(actualEntryPointVA);
        }

        for (auto& insn : allInstructions) {
            if (ZydisMnemonicGetString(insn.instr.mnemonic) == std::string("call") && insn.instr.operand_count > 0) {
                if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    funcStarts.insert(insn.operands[0].imm.value.u);
                    m_calledFuncs.insert(insn.operands[0].imm.value.u);
                }
            }
        }

        size_t i = 0;
        bool assignedEntryPoint = false;
        while (i < allInstructions.size()) {
            Function func;
            func.startAddr = allInstructions[i].addr;
            
            if (func.startAddr == actualEntryPointVA && !assignedEntryPoint) {
                func.name = "entry_point";
                func.isDead = false;
                assignedEntryPoint = true;
            } else {
                func.name = "sub_" + ToHex(func.startAddr);
                func.isDead = true;
            }
            
            func.blocks.push_back({});

            while (i < allInstructions.size()) {
                if (i > 0 && funcStarts.count(allInstructions[i].addr) && allInstructions[i].addr != func.startAddr) break;
                Insn& insn = allInstructions[i];
                std::string m = ZydisMnemonicGetString(insn.instr.mnemonic);
                
                if (m == "int3" || m == "nop" || m == "endbr64" || m == "invalid") { i++; continue; }

                if (m == "call" || m == "add" || m == "sub" || m == "xor" || m.rfind("j", 0) == 0 || m == "ret") func.isDead = false;
                
                PCodeStmt stmt;
                stmt.addr = insn.addr;
                stmt.op = "UNK";
                stmt.dst = ""; stmt.src1 = ""; stmt.src2 = ""; stmt.jumpTarget = 0;

                auto GetOpStr = [&](int idx) -> std::string {
                    if (idx >= insn.instr.operand_count) return "";
                    auto& op = insn.operands[idx];
                    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) return GetRegName(op.reg.value);
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) return "0x" + ToHex(op.imm.value.u);
                    if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        std::string res = "MEM(";
                        if (op.mem.base != ZYDIS_REGISTER_NONE) res += GetRegName(op.mem.base);
                        if (op.mem.disp.value != 0) res += (op.mem.disp.value > 0 ? "+" : "") + std::to_string(op.mem.disp.value);
                        res += ")";
                        return res;
                    }
                    return "unknown";
                };

                if (m == "mov" || m == "movzx" || m == "movsxd" || m == "movsx") {
                    stmt.op = "MOV"; stmt.dst = GetOpStr(0); stmt.src1 = GetOpStr(1);
                }
                else if (m == "lea") {
                    stmt.op = "LEA"; stmt.dst = GetOpStr(0);
                    if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && insn.operands[1].mem.base == ZYDIS_REGISTER_RIP) {
                        uint64_t target = insn.addr + insn.instr.length + insn.operands[1].mem.disp.value;
                        stmt.src1 = "STR_" + ToHex(target);
                    } else stmt.src1 = GetOpStr(1);
                }
                else if (m == "add" || m == "sub" || m == "xor" || m == "and" || m == "or" || m == "shl" || m == "shr" || m == "sar") {
                    stmt.op = "ALU"; stmt.dst = GetOpStr(0); stmt.src1 = m; stmt.src2 = GetOpStr(1);
                }
                else if (m == "inc" || m == "dec" || m == "neg" || m == "not") {
                    stmt.op = "ALU"; stmt.dst = GetOpStr(0); stmt.src1 = m; stmt.src2 = "1"; 
                }
                else if (m == "cmp" || m == "test") {
                    stmt.op = "CMP"; stmt.dst = GetOpStr(0); stmt.src1 = (m == "test") ? "0" : GetOpStr(1);
                }
                else if (m == "call") {
                    stmt.op = "CALL";
                    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        stmt.src1 = "sub_" + ToHex(insn.operands[0].imm.value.u);
                    } 
                    else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && insn.operands[0].mem.base == ZYDIS_REGISTER_RIP) {
                        uint64_t targetAddr = insn.addr + insn.instr.length + insn.operands[0].mem.disp.value;
                        std::string apiName = m_apiResolver->GetApiName(targetAddr);
                        if (!apiName.empty()) stmt.src1 = "api_" + apiName;
                        else stmt.src1 = "((void(*)())MEM(0x" + ToHex(targetAddr) + "))";
                    } else stmt.src1 = GetOpStr(0);
                }
                else if (m.rfind("j", 0) == 0) {
                    stmt.op = (m == "jmp") ? "JMP" : "CJMP"; stmt.src1 = m;
                    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) stmt.jumpTarget = insn.operands[0].imm.value.u;
                }
                else if (m == "ret") { stmt.op = "RET"; }
                else if (m == "push") { stmt.op = "PUSH"; stmt.src1 = GetOpStr(0); }
                else if (m == "pop") { stmt.op = "POP"; stmt.dst = GetOpStr(0); }

                if (stmt.op != "UNK") func.blocks.back().pcode.push_back(stmt);
                i++;
                if (m == "ret") break;
            }
            
            if (func.name == "entry_point" && func.blocks[0].pcode.empty()) {
                PCodeStmt dummy;
                dummy.op = "NOP";
                dummy.addr = func.startAddr;
                func.blocks[0].pcode.push_back(dummy);
            }
            
            m_functions.push_back(func);
        }
    }

    void BuildCFG(Function& func) {
        std::set<uint64_t> leaders;
        if (!func.blocks.empty() && !func.blocks[0].pcode.empty()) leaders.insert(func.blocks[0].pcode[0].addr);
        for (auto& block : func.blocks) {
            for (auto& stmt : block.pcode) {
                if (stmt.op == "JMP" || stmt.op == "CJMP") leaders.insert(stmt.jumpTarget);
            }
        }
        if (func.blocks.empty()) func.blocks.push_back({});
        func.blocks[0].id = 0;
        func.blocks[0].startAddr = func.startAddr;
    }

    void BuildDominatorTree(Function& func) {
        if (func.blocks.empty()) return;
        int N = func.blocks.size();
        std::vector<int> rpo; std::vector<int> rpo_index(N, -1);
        for (int i = 0; i < N; ++i) { rpo.push_back(i); rpo_index[i] = i; }
        func.blocks[0].idom = 0;
        bool changed = true;
        while (changed) {
            changed = false;
            for (int b : rpo) {
                if (b == 0) continue;
                int new_idom = -1;
                for (int p : func.blocks[b].predecessors) {
                    if (func.blocks[p].idom != -1) {
                        if (new_idom == -1) new_idom = p;
                        else {
                            int f1 = p, f2 = new_idom;
                            while (f1 != f2) {
                                while (rpo_index[f1] > rpo_index[f2]) f1 = func.blocks[f1].idom;
                                while (rpo_index[f2] > rpo_index[f1]) f2 = func.blocks[f2].idom;
                            }
                            new_idom = f1;
                        }
                    }
                }
                if (new_idom != -1 && func.blocks[b].idom != new_idom) {
                    func.blocks[b].idom = new_idom;
                    changed = true;
                }
            }
        }
    }

    void FindLoops(Function& func) {
        for (auto& block : func.blocks) {
            for (int succ : block.successors) {
                int curr = block.id;
                while (curr != -1) {
                    if (curr == succ) { func.blocks[succ].isLoopHeader = true; break; }
                    curr = func.blocks[curr].idom;
                }
            }
        }
    }

    std::string EmitFunction(const Function& func) {
        std::stringstream ss;
        ss << "void " << func.name << "(int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4) {\n";

        bool hasRealCode = false;
        for (auto& block : func.blocks) {
            if (block.isLoopHeader) ss << "    while (1) { // Loop Header\n";
            for (auto& stmt : block.pcode) {
                if (stmt.op == "MOV") {
                    ss << "    " << stmt.dst << " = " << stmt.src1 << ";\n"; hasRealCode = true;
                } else if (stmt.op == "LEA") {
                    if (stmt.src1.find("STR_") == 0) {
                        uint64_t addr = std::stoull(stmt.src1.substr(4), nullptr, 16);
                        auto it = m_strings.find(addr);
                        if (it != m_strings.end()) ss << "    " << stmt.dst << " = (uint64_t)\"" << it->second << "\";\n";
                        else ss << "    " << stmt.dst << " = (uint64_t)&MEM(" << ToHex(addr - m_imageBase) << ");\n";
                    } else ss << "    " << stmt.dst << " = (uint64_t)&" << stmt.src1 << ";\n";
                    hasRealCode = true;
                } else if (stmt.op == "ALU") {
                    if (stmt.src1 == "inc") ss << "    " << stmt.dst << "++;\n";
                    else if (stmt.src1 == "dec") ss << "    " << stmt.dst << "--;\n";
                    else if (stmt.src1 == "neg") ss << "    " << stmt.dst << " = -" << stmt.dst << ";\n";
                    else if (stmt.src1 == "not") ss << "    " << stmt.dst << " = ~" << stmt.dst << ";\n";
                    else {
                        std::string opStr = (stmt.src1 == "add") ? "+" : (stmt.src1 == "sub") ? "-" : (stmt.src1 == "xor") ? "^" : (stmt.src1 == "and") ? "&" : (stmt.src1 == "or") ? "|" : (stmt.src1 == "shl") ? "<<" : ">>";
                        ss << "    " << stmt.dst << " " << opStr << "= " << stmt.src2 << ";\n";
                    }
                    hasRealCode = true;
                } else if (stmt.op == "CMP") {
                    ss << "    // CMP " << stmt.dst << ", " << stmt.src1 << "\n"; hasRealCode = true;
                } else if (stmt.op == "CALL") {
                    ss << "    " << stmt.src1 << "(rcx, rdx, r8, r9);\n"; hasRealCode = true;
                } else if (stmt.op == "CJMP") {
                    std::string cond = (stmt.src1 == "jnz" || stmt.src1 == "jne") ? "!=" : (stmt.src1 == "jg") ? ">" : (stmt.src1 == "jl") ? "<" : "==";
                    ss << "    if (!(rax " << cond << " 0)) break;\n"; hasRealCode = true;
                } else if (stmt.op == "RET") {
                    ss << "    return;\n"; hasRealCode = true;
                } else if (stmt.op == "PUSH") {
                    ss << "    // push_stack(" << stmt.src1 << ");\n"; hasRealCode = true;
                } else if (stmt.op == "POP") {
                    ss << "    " << stmt.dst << " = pop_stack();\n"; hasRealCode = true;
                } else if (stmt.op == "NOP") {
                    ss << "    // NOP placeholder\n"; hasRealCode = true;
                }
            }
            if (block.isLoopHeader) ss << "    }\n";
        }
        
        if (!hasRealCode) {
            ss << "    // [WARNING] This function has no valid decoded instructions.\n";
        }
        
        ss << "}\n\n";
        return ss.str();
    }

    std::string ToHex(uint64_t val) { std::stringstream ss; ss << std::hex << val; return ss.str(); }
};

// =========================================================
// 主程序
// =========================================================
int main(int argc, char* argv[]) {
    std::cout << "--- Disasm Engine Started ---\n";
    std::string exePath, cOutputPath;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-f" && i + 1 < argc) exePath = argv[++i];
        else if (arg == "-c" && i + 1 < argc) cOutputPath = argv[++i];
    }
    if (exePath.empty() || cOutputPath.empty()) return 1;

    std::ifstream file(exePath, std::ios::binary | std::ios::ate);
    if (!file) { std::cerr << "Error: Cannot open file.\n"; return 1; }
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> fileData((size_t)fileSize);
    file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    file.close();
    
    std::cout << "[+] File Loaded. Size: " << fileSize << " bytes.\n";

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] Not a valid PE file (missing MZ signature).\n"; return 1;
    }
    const uint8_t* ntBase = fileData.data() + dosHeader->e_lfanew;
    
    // 兼容 32/64 位 PE 头
    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + 4);
    const uint16_t magic = *reinterpret_cast<const uint16_t*>(ntBase + 4 + sizeof(IMAGE_FILE_HEADER));
    
    bool is64Bit = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    uint64_t imageBase, entryPointVA;
    if (is64Bit) {
        const auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(ntBase + 4 + sizeof(IMAGE_FILE_HEADER));
        imageBase = opt->ImageBase;
        entryPointVA = imageBase + opt->AddressOfEntryPoint;
    } else {
        const auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(ntBase + 4 + sizeof(IMAGE_FILE_HEADER));
        imageBase = opt->ImageBase;
        entryPointVA = imageBase + opt->AddressOfEntryPoint;
    }

    ApiResolver apiResolver;
    // 使用兼容后的头信息进行导入表解析
    const auto* ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(ntBase);
    apiResolver.LoadImports(fileData.data(), fileSize, ntHeader, imageBase);
    std::cout << "[+] Imports Parsed.\n";

    const uint8_t* sectionStart = ntBase + 4 + sizeof(IMAGE_FILE_HEADER) + fileHeader->SizeOfOptionalHeader;
    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(sectionStart);

    // 【核心修复】智能寻找代码节
    std::cout << "[DEBUG] Section Table:\n";
    const IMAGE_SECTION_HEADER* targetSection = nullptr;
    for (int i = 0; i < fileHeader->NumberOfSections; ++i) {
        std::cout << "  [" << i << "] " << std::setw(8) << std::setfill('\0') << (const char*)sections[i].Name 
                  << " VA: 0x" << std::hex << sections[i].VirtualAddress 
                  << " SizeOfRawData: " << std::dec << sections[i].SizeOfRawData
                  << " Characteristics: 0x" << std::hex << sections[i].Characteristics << "\n";

        // 如果是 .text，或者有可执行/代码属性且大小大于0，就选它
        if (sections[i].SizeOfRawData > 0) {
            if (strncmp((const char*)sections[i].Name, ".text", 5) == 0) {
                targetSection = &sections[i];
                break; // 优先 .text
            }
            if (!targetSection && (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                targetSection = &sections[i]; // 次选可执行节
            }
        }
    }

    if (!targetSection) {
        // 如果都没有，就随便找个有数据的节
        for (int i = 0; i < fileHeader->NumberOfSections; ++i) {
            if (sections[i].SizeOfRawData > 0) {
                targetSection = &sections[i];
                break;
            }
        }
    }

    if (!targetSection) {
        std::cerr << "[-] No executable section with raw data found.\n";
        return 1;
    }

    std::cout << "[DEBUG] Selected Section: " << (const char*)targetSection->Name 
              << " (Size: " << std::dec << targetSection->SizeOfRawData << " bytes).\n";

    const uint8_t* codeData = fileData.data() + targetSection->PointerToRawData;
    uint32_t rawSize = targetSection->SizeOfRawData;
    uint64_t virtualBase = imageBase + targetSection->VirtualAddress;

    // 【核心修复】根据 32/64 位模式初始化 Zydis 解码器
    ZydisDecoder decoder;
    if (is64Bit) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    }

    std::vector<Insn> allInstructions;
    ZyanUSize offset = 0;
    while (offset < rawSize) {
        Insn insn;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, codeData + offset, rawSize - offset, &insn.instr, insn.operands))) {
            insn.addr = virtualBase + offset;
            allInstructions.push_back(insn);
            offset += insn.instr.length;
        } else offset += 1;
    }
    
    std::cout << "[+] Disassembled " << allInstructions.size() << " instructions.\n";

    UltimateDecompiler decompiler(&apiResolver);
    // 这里的 LoadStrings 需要真实的 ntHeader，可能是 32 位也可能是 64 位
    decompiler.LoadStrings(fileData.data(), fileSize, ntHeader, imageBase);
    
    decompiler.AnalyzeAllFunctions(allInstructions, imageBase, entryPointVA);
    
    decompiler.WriteToFile(cOutputPath, allInstructions);

    std::cout << "[SUCCESS] Decompilation complete!\n";
    std::cout << "Output saved to: " << cOutputPath << "\n";
    return 0;
}
