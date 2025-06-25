#include <string>
#include <filesystem>
#include "src/patcher/patcher.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: pe_patcher <path_to_pe_file>\n";
        return 1;
    }

    std::string filename = argv[1];
    if (!std::filesystem::is_regular_file(filename)) {
        std::cerr << "[-] Not a valid file: " << filename << "\n";
        return 1;
    }

    std::cout << "[*] Patching: " << filename << "\n";
    if (!patcher::patch_pe(filename)) {
        std::cerr << "[-] Failed to patch the PE file.\n";
        return 1;
    }

    std::cout << "[+] PE file successfully patched.\n";
    return 0;
}