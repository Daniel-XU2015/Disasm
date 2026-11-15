/*
 * Disasm - Lightweight PE Disassembler & Decompiler
 * Copyright (c) 2026 [Daniel-XU2015]
 *
 * This project is licensed under the MIT License.
 * See the LICENSE file in the root directory for details.
 */

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
// API 签名库
// =========================================================
struct ApiParam {
    std::string type;
    bool isString;
    ApiParam(std::string t, bool s) : type(t), isString(s) {}
};

struct ApiSignature {
    std::string name;
    std::vector<ApiParam> params;
};

class ApiDatabase {
public:
    ApiDatabase() {
        Add("MessageBoxA", { { "HWND", false },{ "LPCSTR", true },{ "LPCSTR", true },{ "UINT", false } });
        Add("ExitProcess", { { "UINT", false } });
        Add("GetCommandLineA", {});
    }

    bool GetSignature(const std::string& name, ApiSignature& outSig) {
        if (m_db.count(name)) { outSig = m_db[name]; return true; }
        return false;
    }

private:
    std::unordered_map<std::string, ApiSignature> m_db;
    void Add(const std::string& name, std::vector<ApiParam> params) {
        m_db[name] = { name, params };
    }
};

// =========================================================
// 数据结构定义
// =========================================================
struct Insn {
    uint64_t addr;
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
};

struct BasicBlock {
    uint64_t startAddr;
    std::vector<Insn> instructions;
    uint64_t jumpTarget;
    bool isConditional;
};

struct LocalVarInfo {
    int64_t offset;
    int size;
    std::string type;
};

struct Symbol {
    std::string expr;
    bool isString = false;
    std::string strVal;
};

struct Function {
    uint64_t startAddr;
    std::string name;
    std::vector<Insn> instructions;
    std::vector<BasicBlock> blocks;
    std::map<int64_t, LocalVarInfo> localVars;
    std::set<uint64_t> jumpLabels;
    bool isDead;
    std::string generatedCode;
};

class ApiResolver {
public:
    void LoadImports(const uint8_t* fileData, size_t fileSize, const IMAGE_NT_HEADERS* ntHeader, uint64_t imageBase) {
        uint32_t importRva = 0;
        if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            importRva = reinterpret_cast<const IMAGE_NT_HEADERS32*>(ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        }
        else {
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
        if (it != m_iatMap.end()) return it->second;
        return "";
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
// 终极反编译引擎（包含终极优化）
// =========================================================
class AdvancedDecompiler {
public:
    AdvancedDecompiler(ApiResolver* resolver, bool is64Bit)
        : m_apiResolver(resolver), m_is64Bit(is64Bit) {
    }

    void LoadStrings(const uint8_t* fileData, size_t fileSize, const IMAGE_NT_HEADERS* ntHeader, uint64_t imageBase) {
        const auto* section = IMAGE_FIRST_SECTION(ntHeader);
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
            std::string secName(reinterpret_cast<const char*>(section[i].Name), strnlen(reinterpret_cast<const char*>(section[i].Name), 8));
            // 【修复1】扫描 .rdata 和 .data 段
            if (secName == ".rdata" || secName == ".data") {
                const uint8_t* data = fileData + section[i].PointerToRawData;
                uint32_t size = section[i].SizeOfRawData;
                uint64_t va = imageBase + section[i].VirtualAddress;
                std::string currentStr;
                uint64_t currentStart = 0;
                for (uint32_t j = 0; j < size; ++j) {
                    char c = (char)data[j];
                    if (c >= 32 && c <= 126) {
                        if (currentStr.empty()) currentStart = va + j;
                        currentStr += c;
                    }
                    else if (c == 0) {
                        // 【修复2】放宽长度限制到 1，防止单字符截断
                        if (currentStr.length() >= 1) m_strings[currentStart] = currentStr;
                        currentStr.clear();
                    }
                    else currentStr.clear();
                }
            }
        }
    }

    void AnalyzeAllFunctions(std::vector<Insn>& allInstructions, uint64_t imageBase) {
        m_imageBase = imageBase;
        CleanGarbageData(allInstructions);
        FindFunctions(allInstructions);

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

                    AnalyzeVariables(func);
                    BuildCFG(func);
                    func.generatedCode = EmitFunction(func);
                }
                });
        }

        for (auto& th : threads) th.join();
    }

    void WriteToFile(const std::string& outPath, const uint8_t* fileData, size_t fileSize, const IMAGE_NT_HEADERS* ntHeader) {
        std::ofstream out(outPath);
        out << "\xEF\xBB\xBF";

        out << "#include <stdint.h>\n#include <windows.h>\n\n";
        out << "uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15;\n";
        out << "uint8_t memory[0x100000];\n";
        out << "#define MEM(a) memory[(uint32_t)(a) & 0xFFFFF]\n\n";

        out << "// --- API Mapping ---\n";
        for (auto& api : m_usedApis) {
            out << "#define api_" << api << " " << api << "\n";
        }
        out << "\n";

        for (const auto& func : m_functions) {
            if (!func.isDead && !func.generatedCode.empty()) {
                if (func.name == "entry_point" || m_calledFuncs.count(func.startAddr)) {
                    out << func.generatedCode << "\n";
                }
            }
        }

        out << "int main() {\n";
        if (!m_functions.empty()) {
            for (const auto& f : m_functions) {
                if (!f.isDead && f.name == "entry_point") {
                    out << "    " << f.name << "(0, 0, 0, 0);\n";
                    break;
                }
            }
        }
        out << "    return 0;\n}\n";
    }

private:
    uint64_t m_imageBase;
    bool m_is64Bit;
    ApiResolver* m_apiResolver;
    ApiDatabase m_apiDb;
    std::vector<Function> m_functions;
    std::unordered_map<uint64_t, std::string> m_strings;
    std::set<uint64_t> m_calledFuncs;
    std::set<std::string> m_usedApis;

    void CleanGarbageData(std::vector<Insn>& allInstructions) {
        allInstructions.erase(std::remove_if(allInstructions.begin(), allInstructions.end(), [](const Insn& insn) {
            std::string m = ZydisMnemonicGetString(insn.instr.mnemonic);
            return m == "int3" || m == "invalid";
            }), allInstructions.end());
    }

    void FindFunctions(std::vector<Insn>& allInstructions) {
        std::set<uint64_t> funcStarts;
        if (!allInstructions.empty()) funcStarts.insert(allInstructions.front().addr);

        for (auto& insn : allInstructions) {
            if (ZydisMnemonicGetString(insn.instr.mnemonic) == "call" && insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                uint64_t target = insn.operands[0].imm.value.u;
                funcStarts.insert(target);
                m_calledFuncs.insert(target);
            }
        }

        size_t i = 0;
        while (i < allInstructions.size()) {
            Function func;
            func.startAddr = allInstructions[i].addr;
            func.name = (i == 0) ? "entry_point" : "sub_" + ToHex(func.startAddr);
            func.isDead = true;

            while (i < allInstructions.size()) {
                Insn& insn = allInstructions[i];
                if (i > 0 && funcStarts.count(insn.addr)) break;
                func.instructions.push_back(insn);
                i++;

                std::string m = ZydisMnemonicGetString(insn.instr.mnemonic);
                if (m == "call" || m == "add" || m == "sub" || m == "xor" || m.rfind("j", 0) == 0) func.isDead = false;
                if (m == "ret") break;
            }
            m_functions.push_back(func);
        }
    }

    void AnalyzeVariables(Function& func) {
        for (auto& insn : func.instructions) {
            for (int i = 0; i < insn.instr.operand_count; ++i) {
                auto& op = insn.operands[i];
                if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RBP && op.mem.disp.value < 0) {
                    int64_t disp = op.mem.disp.value;
                    int size = op.size;
                    if (!func.localVars.count(disp) || func.localVars[disp].size < size) {
                        func.localVars[disp].offset = disp;
                        func.localVars[disp].size = size;
                        if (size == 64) func.localVars[disp].type = "int64_t";
                        else if (size == 32) func.localVars[disp].type = "int32_t";
                        else if (size == 16) func.localVars[disp].type = "int16_t";
                        else func.localVars[disp].type = "int8_t";
                    }
                }
            }
        }
    }

    void BuildCFG(Function& func) {
        std::set<uint64_t> leaders;
        if (!func.instructions.empty()) leaders.insert(func.instructions[0].addr);
        for (auto& insn : func.instructions) {
            std::string m = ZydisMnemonicGetString(insn.instr.mnemonic);
            if (m.rfind("j", 0) == 0) {
                if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) leaders.insert(insn.operands[0].imm.value.u);
                if (&insn != &func.instructions.back()) leaders.insert(insn.addr + insn.instr.length);
            }
        }

        BasicBlock current;
        for (auto& insn : func.instructions) {
            if (leaders.count(insn.addr)) {
                if (!current.instructions.empty()) { func.blocks.push_back(current); current = BasicBlock(); }
                current.startAddr = insn.addr;
                current.jumpTarget = 0;
                current.isConditional = false;
            }
            current.instructions.push_back(insn);

            std::string m = ZydisMnemonicGetString(insn.instr.mnemonic);
            if (m == "ret" || m == "jmp" || m.rfind("j", 0) == 0) {
                if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    current.jumpTarget = insn.operands[0].imm.value.u;
                    current.isConditional = (m != "jmp");
                }
                func.blocks.push_back(current); current = BasicBlock();
            }
        }
        if (!current.instructions.empty()) func.blocks.push_back(current);
    }

    std::string EmitFunction(const Function& func) {
        std::stringstream ss;
        bool hasRealCode = false;
        ss << "void " << func.name << "(int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4) {\n";

        for (const auto& pair : func.localVars) {
            ss << "    " << pair.second.type << " var_" << -pair.second.offset << " = 0;\n";
        }

        std::unordered_map<ZydisRegister, Symbol> regSyms;
        std::unordered_map<int64_t, Symbol> memSyms;

        std::string lastCmpLeft, lastCmpRight;
        std::vector<std::pair<std::string, uint64_t>> scopeStack;

        auto getSym = [&](const ZydisDecodedOperand& op) -> Symbol {
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                if (regSyms.count(op.reg.value)) return regSyms[op.reg.value];
                const char* name = ZydisRegisterGetString(op.reg.value);
                return { name ? name : "unknown", false, "" };
            }
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (op.mem.base == ZYDIS_REGISTER_RBP) {
                    int64_t disp = op.mem.disp.value;
                    if (disp < 0) {
                        if (memSyms.count(disp)) return memSyms[disp];
                        return { "var_" + std::to_string(-disp), false, "" };
                    }
                    if (disp > 0) return { "arg_" + std::to_string(disp), false, "" };
                }
                std::string addr = "MEM(";
                if (op.mem.base != ZYDIS_REGISTER_NONE) addr += ZydisRegisterGetString(op.mem.base);
                if (op.mem.disp.value != 0) addr += (op.mem.disp.value > 0 ? "+" : "") + std::to_string(op.mem.disp.value);
                addr += ")";
                return { addr, false, "" };
            }
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                std::stringstream ss2; ss2 << "0x" << std::hex << op.imm.value.u;
                return { ss2.str(), false, "" };
            }
            return { "unknown", false, "" };
            };

        for (auto& block : func.blocks) {
            if (!scopeStack.empty() && scopeStack.back().second == block.startAddr) {
                ss << "    }\n";
                scopeStack.pop_back();
            }

            bool isLoopHead = false;
            for (auto& insn : block.instructions) {
                std::string m = ZydisMnemonicGetString(insn.instr.mnemonic);
                if ((m == "jmp" || m.rfind("j", 0) == 0) && insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    if (insn.operands[0].imm.value.u <= block.startAddr) { isLoopHead = true; break; }
                }
            }
            if (isLoopHead) { ss << "    while (1) {\n"; hasRealCode = true; }

            for (auto& insn : block.instructions) {
                std::string mnemonic = ZydisMnemonicGetString(insn.instr.mnemonic);
                if (mnemonic == "push" || mnemonic == "pop" || mnemonic == "nop" || mnemonic == "leave") continue;
                if (mnemonic == "ret") continue;

                if (mnemonic == "cmp" || mnemonic == "test") {
                    lastCmpLeft = getSym(insn.operands[0]).expr;
                    lastCmpRight = (mnemonic == "test") ? "0" : getSym(insn.operands[1]).expr;
                    continue;
                }
                if (mnemonic.rfind("j", 0) == 0) {
                    std::string cond = (mnemonic == "jnz" || mnemonic == "jne") ? "!=" : (mnemonic == "jg") ? ">" : (mnemonic == "jl") ? "<" : "==";
                    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        uint64_t target = insn.operands[0].imm.value.u;
                        if (target > block.startAddr) {
                            ss << "    if (" << lastCmpLeft << " " << cond << " " << lastCmpRight << ") {\n";
                            scopeStack.push_back({ "if", target });
                        }
                        else {
                            ss << "    if (!(" << lastCmpLeft << " " << cond << " " << lastCmpRight << ")) break;\n";
                        }
                        hasRealCode = true;
                    }
                    continue;
                }

                if (mnemonic == "call") {
                    std::string funcName = "";
                    ApiSignature sig;
                    bool hasSig = false;

                    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && insn.operands[0].mem.base == ZYDIS_REGISTER_RIP) {
                        uint64_t targetAddr = insn.addr + insn.instr.length + insn.operands[0].mem.disp.value;
                        funcName = m_apiResolver->GetApiName(targetAddr);
                        if (!funcName.empty()) {
                            hasSig = m_apiDb.GetSignature(funcName, sig);
                            m_usedApis.insert(funcName);
                        }
                    }
                    if (funcName.empty() && insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) funcName = "sub_" + ToHex(insn.operands[0].imm.value.u);

                    ss << "    " << funcName << "(";
                    std::vector<ZydisRegister> argRegs = { ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9 };

                    for (int i = 0; i < 4; ++i) {
                        Symbol argSym = regSyms.count(argRegs[i]) ? regSyms[argRegs[i]] : Symbol{ "0", false, "" };

                        if (hasSig && i < sig.params.size()) {
                            if (sig.params[i].isString) {
                                if (argSym.isString) {
                                    // 如果溯源到了字符串，直接输出字面量
                                    ss << argSym.strVal;
                                }
                                else if (argSym.expr.find("&MEM") != std::string::npos) {
                                    // 【修复】如果已经是 &MEM(...) 了，直接强转，不要重复套
                                    ss << "(const char*)" << argSym.expr;
                                }
                                else {
                                    // 如果是普通数字，才套 &MEM
                                    ss << "(const char*)&MEM(" << argSym.expr << ")";
                                }
                            }
                            else {
                                ss << "(" << sig.params[i].type << ")" << argSym.expr;
                            }
                        }
                        else {
                            ss << argSym.expr;
                        }
                        if (i < 3) ss << ", ";
                    }
                    ss << ");\n";
                    hasRealCode = true;
                    regSyms.clear();
                    continue;
                }

                if (mnemonic == "lea") {
                    ZydisRegister dstReg = insn.operands[0].reg.value;
                    Symbol sym;
                    if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && insn.operands[1].mem.base == ZYDIS_REGISTER_RIP) {
                        uint64_t targetAddr = insn.addr + insn.instr.length + insn.operands[1].mem.disp.value;
                        auto it = m_strings.find(targetAddr);
                        if (it != m_strings.end()) {
                            sym = { "0x" + ToHex(targetAddr), true, "\"" + it->second + "\"" };
                        }
                        else {
                            sym = { "(uint64_t)&MEM(0x" + ToHex(targetAddr - m_imageBase) + ")", false, "" };
                        }
                    }
                    else {
                        sym = { "(uint64_t)&" + getSym(insn.operands[1]).expr, false, "" };
                    }
                    regSyms[dstReg] = sym;
                    continue;
                }

                if (mnemonic == "mov" || mnemonic == "movzx" || mnemonic == "movsxd") {
                    Symbol srcSym = getSym(insn.operands[1]);

                    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                        regSyms[insn.operands[0].reg.value] = srcSym;
                    }
                    else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && insn.operands[0].mem.base == ZYDIS_REGISTER_RBP) {
                        int64_t disp = insn.operands[0].mem.disp.value;
                        if (disp < 0) {
                            memSyms[disp] = srcSym;
                            if (!srcSym.isString) {
                                ss << "    var_" << -disp << " = " << srcSym.expr << ";\n";
                                hasRealCode = true;
                            }
                        }
                        else {
                            ss << "    arg_" << disp << " = " << srcSym.expr << ";\n";
                            hasRealCode = true;
                        }
                    }
                    continue;
                }

                if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "xor" || mnemonic == "and" || mnemonic == "or") {
                    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                        regSyms.erase(insn.operands[0].reg.value);
                    }
                    else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && insn.operands[0].mem.base == ZYDIS_REGISTER_RBP) {
                        int64_t disp = insn.operands[0].mem.disp.value;
                        if (disp < 0) {
                            memSyms.erase(disp);
                            std::string op = (mnemonic == "add") ? "+" : (mnemonic == "sub") ? "-" : (mnemonic == "xor") ? "^" : (mnemonic == "and") ? "&" : "|";
                            ss << "    var_" << -disp << " " << op << "= " << getSym(insn.operands[1]).expr << ";\n";
                            hasRealCode = true;
                        }
                    }
                    continue;
                }
            }
        }

        while (!scopeStack.empty()) { ss << "    }\n"; scopeStack.pop_back(); }
        if (!hasRealCode) return "void " + func.name + "(int64_t, int64_t, int64_t, int64_t) {}\n";

        ss << "}\n\n";
        return ss.str();
    }

    std::string ToHex(uint64_t val) { std::stringstream ss; ss << std::hex << val; return ss.str(); }
};

// =========================================================
// 主程序
// =========================================================
int main(int argc, char* argv[]) {
    if (argc > 1) {
        std::string arg1 = argv[1];
        if (arg1 == "-help" || arg1 == "-h" || arg1 == "--help") {
            printf("==========================================\n");
            printf(" DisasmPro - Advanced Static Decompiler\n");
            printf("==========================================\n");
            printf("Usage: %s -f <input_exe> -c <output_c_file>\n\n", argv[0]);
            printf("Options:\n");
            printf("  -f <path>    Path to the PE/EXE file to analyze\n");
            printf("  -c <path>    Path to save the decompiled C file\n");
            printf("  -help, -h    Show this help message\n");
            return 0;
        }
    }

    std::string exePath, cOutputPath;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-f" && i + 1 < argc) exePath = argv[++i];
        else if (arg == "-c" && i + 1 < argc) cOutputPath = argv[++i];
    }
    if (exePath.empty() || cOutputPath.empty()) {
        printf("Error: Missing arguments. Use -help for more info.\n");
        return 1;
    }

    std::ifstream file(exePath, std::ios::binary | std::ios::ate);
    if (!file) { printf("Error: Cannot open file.\n"); return 1; }
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> fileData((size_t)fileSize);
    file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    file.close();

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileData.data());
    const uint8_t* ntBase = fileData.data() + dosHeader->e_lfanew;
    const auto* ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(ntBase);

    bool is64Bit = (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    uint64_t imageBase = is64Bit ? reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntHeader)->OptionalHeader.ImageBase
        : reinterpret_cast<const IMAGE_NT_HEADERS32*>(ntHeader)->OptionalHeader.ImageBase;

    ApiResolver apiResolver;
    apiResolver.LoadImports(fileData.data(), fileSize, ntHeader, imageBase);

    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(IMAGE_FIRST_SECTION(ntHeader));
    const IMAGE_SECTION_HEADER* codeSection = nullptr;
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
        if (strncmp(reinterpret_cast<const char*>(sections[i].Name), ".text", 5) == 0) { codeSection = &sections[i]; break; }
    }
    if (!codeSection) { printf("Error: No .text section found.\n"); return 1; }

    const uint8_t* codeData = fileData.data() + codeSection->PointerToRawData;
    uint32_t rawSize = codeSection->SizeOfRawData;
    uint64_t virtualBase = imageBase + codeSection->VirtualAddress;

    ZydisDecoder decoder;
    if (is64Bit) ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    else ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    std::vector<Insn> allInstructions;
    ZyanUSize offset = 0;
    while (offset < rawSize) {
        Insn insn;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, codeData + offset, rawSize - offset, &insn.instr, insn.operands))) {
            insn.addr = virtualBase + offset;
            allInstructions.push_back(insn);
            offset += insn.instr.length;
        }
        else {
            offset += 1;
        }
    }

    AdvancedDecompiler decompiler(&apiResolver, is64Bit);
    decompiler.LoadStrings(fileData.data(), fileSize, ntHeader, imageBase);
    decompiler.AnalyzeAllFunctions(allInstructions, imageBase);
    decompiler.WriteToFile(cOutputPath, fileData.data(), fileSize, ntHeader);

    printf("[SUCCESS] Decompilation complete!\n");
    printf("Output saved to: %s\n", cOutputPath.c_str());
    return 0;
}