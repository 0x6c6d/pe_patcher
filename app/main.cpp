#include <string>
#include <filesystem>
#include "src/patcher/patcher.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: pe_patcher <path_to_pe_file>\n";
        return 1;
    }

    std::string filename = argv[1];
    if (!std::filesystem::is_regular_file(filename)) {
        std::cout << "[-] Not a valid file: " << filename << "\n";
        return 1;
    }

    std::cout << "[*] Patching: " << filename << "\n";
    if (!patcher::patch_pe(filename)) {
        std::cout << "[-] Failed to patch the PE file.\n";
        return 1;
    }

    std::cout << "[+] PE file successfully patched.\n";
    return 0;
}

// TODO: add globals.h & add .section name to it
// TODO: pass a second pe file where the shellcode will be extracted from