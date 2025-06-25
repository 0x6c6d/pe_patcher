#include "patcher.h"
#include "../utils/utils.h"

#pragma comment(lib, "user32.lib")

// MessageBoxA shellcode (32-bit)
const BYTE shellcode32[] = {
    0x6A, 0x00,                               // push 0
    0x68, 0x00, 0x00, 0x00, 0x00,             // push offset "Caption"
    0x68, 0x00, 0x00, 0x00, 0x00,             // push offset "Text"
    0x6A, 0x00,                               // push 0
    0xB8, 0x00, 0x00, 0x00, 0x00,             // mov eax, addr of MessageBoxA
    0xFF, 0xD0,                               // call eax
    0xE9, 0x00, 0x00, 0x00, 0x00              // jmp original_entry
};

// MessageBoxA shellcode (64-bit) — uses syscall-like ABI
const BYTE shellcode64[] = {
    0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28
    0x48, 0x31, 0xC9,                         // xor rcx, rcx
    0x48, 0xB8, 0,0,0,0,0,0,0,0,              // mov rax, &text
    0x48, 0x89, 0xC2,                         // mov rdx, rax
    0x48, 0xB8, 0,0,0,0,0,0,0,0,              // mov rax, &caption
    0x49, 0x89, 0xC0,                         // mov r8, rax
    0x49, 0xB8, 0,0,0,0,0,0,0,0,              // mov r8, &MessageBoxA
    0x41, 0xFF, 0xD0,                         // call r8
    0x48, 0x83, 0xC4, 0x28,                   // add rsp, 0x28
    0xE9, 0,0,0,0                             // jmp original entry
};

#pragma region Helper
// adding to .text section
bool patch_x64_add_to_text(std::vector<char>& data, DWORD peOffset)
{
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)&data[peOffset];
    IMAGE_OPTIONAL_HEADER64* opt = &nt->OptionalHeader;
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    // Find .text section
    IMAGE_SECTION_HEADER* text = nullptr;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (strncmp((char*)sections[i].Name, ".text", 5) == 0) {
            text = &sections[i];
            break;
        }
    }

    if (!text) {
        std::cerr << "[-] .text section not found.\n";
        return false;
    }

    DWORD textRawOffset = text->PointerToRawData;
    DWORD textRawSize = text->SizeOfRawData;
    DWORD textVA = text->VirtualAddress;

    // Shellcode
    BYTE patch[sizeof(shellcode64)];
    memcpy(patch, shellcode64, sizeof(shellcode64));

    const char* msg = "Hello from x64 MessageBoxA!";
    const char* cap = "Injected!";
    size_t msgLen = strlen(msg) + 1;
    size_t capLen = strlen(cap) + 1;

    size_t totalNeeded = sizeof(patch) + msgLen + capLen;

    for (DWORD offset = 0; offset <= textRawSize - totalNeeded; ++offset) {
        bool fits = true;
        for (size_t i = 0; i < totalNeeded; ++i) {
            if (data[textRawOffset + offset + i] != 0x00) {
                fits = false;
                break;
            }
        }

        if (fits) {
            DWORD shellOffset = textRawOffset + offset;
            DWORD msgOffset = shellOffset + sizeof(patch);
            DWORD capOffset = msgOffset + msgLen;

            memcpy(&data[msgOffset], msg, msgLen);
            memcpy(&data[capOffset], cap, capLen);

            ULONGLONG baseVA = opt->ImageBase + textVA + offset;

            *(ULONGLONG*)(patch + 9) = baseVA + sizeof(patch);               // msg
            *(ULONGLONG*)(patch + 20) = baseVA + sizeof(patch) + msgLen;      // cap

            HMODULE user32 = LoadLibraryA("user32.dll");
            FARPROC msgbox = GetProcAddress(user32, "MessageBoxA");
            if (!msgbox) {
                std::cerr << "[-] Failed to resolve MessageBoxA.\n";
                return false;
            }
            *(ULONGLONG*)(patch + 31) = (ULONGLONG)msgbox;

            // Calculate jump offset to original EP
            DWORD originalEP = opt->AddressOfEntryPoint;
            *(DWORD*)(patch + sizeof(patch) - 4) = originalEP - (textVA + offset + sizeof(patch));

            memcpy(&data[shellOffset], patch, sizeof(patch));

            opt->AddressOfEntryPoint = textVA + offset;

            std::cout << "[+] Injected shellcode into .text section (x64).\n";
            return true;
        }
    }

    std::cerr << "[-] Not enough space in .text section for x64 shellcode.\n";
    return false;
}

bool patch_x86_add_to_text(std::vector<char>& data, DWORD peOffset)
{
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)&data[peOffset];
    IMAGE_OPTIONAL_HEADER32* opt = &nt->OptionalHeader;
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    // Find .text section
    IMAGE_SECTION_HEADER* text = nullptr;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (strncmp((char*)sections[i].Name, ".text", 5) == 0) {
            text = &sections[i];
            break;
        }
    }

    if (!text) {
        std::cerr << "[-] .text section not found.\n";
        return false;
    }

    DWORD textRawOffset = text->PointerToRawData;
    DWORD textRawSize = text->SizeOfRawData;
    DWORD textVA = text->VirtualAddress;

    // Shellcode
    BYTE patch[sizeof(shellcode32)];
    memcpy(patch, shellcode32, sizeof(shellcode32));

    const char* msg = "Hello from text MessageBoxA!";
    const char* cap = "Injected!";
    size_t msgLen = strlen(msg) + 1;
    size_t capLen = strlen(cap) + 1;

    // Estimate total space needed
    size_t totalNeeded = sizeof(patch) + msgLen + capLen;

    // Search for a block of nulls in the .text section
    for (DWORD offset = 0; offset <= textRawSize - totalNeeded; ++offset) {
        bool fits = true;
        for (size_t i = 0; i < totalNeeded; ++i) {
            if (data[textRawOffset + offset + i] != 0x00) {
                fits = false;
                break;
            }
        }

        if (fits) {
            DWORD shellOffset = textRawOffset + offset;
            DWORD msgOffset = shellOffset + sizeof(patch);
            DWORD capOffset = msgOffset + msgLen;

            // Write strings
            memcpy(&data[msgOffset], msg, msgLen);
            memcpy(&data[capOffset], cap, capLen);

            // Patch shellcode with addresses
            *(DWORD*)(patch + 3) = opt->ImageBase + textVA + offset + sizeof(patch) + msgLen; // cap
            *(DWORD*)(patch + 8) = opt->ImageBase + textVA + offset + sizeof(patch);          // msg
            HMODULE user32 = LoadLibraryA("user32.dll");
            FARPROC msgbox = GetProcAddress(user32, "MessageBoxA");
            if (!msgbox) {
                std::cerr << "[-] Failed to resolve MessageBoxA.\n";
                return false;
            }
            *(DWORD*)(patch + 13) = (DWORD)(DWORD_PTR)msgbox;
            *(DWORD*)(patch + 17) = opt->AddressOfEntryPoint - (textVA + offset + sizeof(patch));

            // Inject shellcode
            memcpy(&data[shellOffset], patch, sizeof(patch));

            // Redirect entry point
            opt->AddressOfEntryPoint = textVA + offset;

            std::cout << "[+] Injected shellcode into .text section.\n";
            return true;
        }
    }

    std::cerr << "[-] Not enough space in .text section for shellcode.\n";
    return false;
}

// adding new section
bool has_space_for_new_section_header_x64(IMAGE_NT_HEADERS64* nt, DWORD peOffset, size_t fileSize)
{
    WORD currentSections = nt->FileHeader.NumberOfSections;
    DWORD sectionHeaderOffset = peOffset + sizeof(IMAGE_NT_HEADERS64);
    DWORD nextSectionHeaderEnd = sectionHeaderOffset + ((currentSections + 1) * sizeof(IMAGE_SECTION_HEADER));

    return nextSectionHeaderEnd <= nt->OptionalHeader.SizeOfHeaders && nextSectionHeaderEnd <= fileSize;
}

bool has_space_for_new_section_header_x86(IMAGE_NT_HEADERS32* nt, DWORD peOffset, size_t fileSize)
{
    WORD currentSections = nt->FileHeader.NumberOfSections;
    DWORD sectionHeaderOffset = peOffset + sizeof(IMAGE_NT_HEADERS32);
    DWORD nextSectionHeaderEnd = sectionHeaderOffset + ((currentSections + 1) * sizeof(IMAGE_SECTION_HEADER));

    return nextSectionHeaderEnd <= nt->OptionalHeader.SizeOfHeaders &&
        nextSectionHeaderEnd <= fileSize;
}

bool patch_x64_add_new_section(std::vector<char>& data, DWORD peOffset)
{
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)&data[peOffset];
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    IMAGE_OPTIONAL_HEADER64* opt = &nt->OptionalHeader;

    auto& last = sections[nt->FileHeader.NumberOfSections - 1];
    DWORD newRVA = utils::AlignUp(last.VirtualAddress + last.Misc.VirtualSize, opt->SectionAlignment);
    DWORD newRaw = utils::AlignUp(last.PointerToRawData + last.SizeOfRawData, opt->FileAlignment);

    if (!has_space_for_new_section_header_x64(nt, peOffset, data.size())) {
        std::cerr << "[-] Not enough space in PE headers for new section header.\n";
        return false;
    }

    // Add .msgbox section
    IMAGE_SECTION_HEADER newSec = {};
    memcpy(newSec.Name, ".msgbox", 7);
    newSec.VirtualAddress = newRVA;
    newSec.PointerToRawData = newRaw;
    newSec.Misc.VirtualSize = 0x1000;
    newSec.SizeOfRawData = 0x1000;
    newSec.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    memcpy(&sections[nt->FileHeader.NumberOfSections], &newSec, sizeof(newSec));
    nt->FileHeader.NumberOfSections++;
    opt->SizeOfImage = newSec.VirtualAddress + newSec.Misc.VirtualSize;

    if (newRaw + 0x1000 > data.max_size()) {
        std::cerr << "[-] File too large after resizing.\n";
        return false;
    }

    data.resize(newRaw + 0x1000, 0x00);

    DWORD originalEP = opt->AddressOfEntryPoint;

    BYTE patch[sizeof(shellcode64)];
    memcpy(patch, shellcode64, sizeof(shellcode64));

    // Insert dummy message and caption
    const char* msg = "Hello from injected MessageBoxA!";
    const char* cap = "Patched!";
    DWORD msgOffset = newRaw + 0x100;
    DWORD capOffset = msgOffset + strlen(msg) + 1;

    if (capOffset + strlen(cap) + 1 > data.size()) {
        std::cerr << "[-] Not enough space for strings.\n";
        return false;
    }

    std::memcpy(&data[msgOffset], msg, strlen(msg) + 1);
    std::memcpy(&data[capOffset], cap, strlen(cap) + 1);

    // Patch pointers in shellcode (text, caption, MessageBoxA)
    *(ULONGLONG*)(patch + 9) = opt->ImageBase + newSec.VirtualAddress + 0x100; // msg
    *(ULONGLONG*)(patch + 20) = opt->ImageBase + newSec.VirtualAddress + 0x100 + strlen(msg) + 1; // cap
    HMODULE user32 = LoadLibraryA("user32.dll");
    FARPROC msgbox = GetProcAddress(user32, "MessageBoxA");
    if (!msgbox) {
        std::cerr << "[-] Failed to resolve MessageBoxA.\n";
        return false;
    }

    *(ULONGLONG*)(patch + 31) = (ULONGLONG)msgbox;
    *(DWORD*)(patch + sizeof(patch) - 4) = originalEP - newSec.VirtualAddress - sizeof(patch);

    memcpy(&data[newRaw], patch, sizeof(patch));
    opt->AddressOfEntryPoint = newSec.VirtualAddress;

    return true;
}

bool patch_x86_add_new_section(std::vector<char>& data, DWORD peOffset)
{
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)&data[peOffset];
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    IMAGE_OPTIONAL_HEADER32* opt = &nt->OptionalHeader;

    auto& last = sections[nt->FileHeader.NumberOfSections - 1];
    DWORD newRVA = utils::AlignUp(last.VirtualAddress + last.Misc.VirtualSize, opt->SectionAlignment);
    DWORD newRaw = utils::AlignUp(last.PointerToRawData + last.SizeOfRawData, opt->FileAlignment);

    if (!has_space_for_new_section_header_x86(nt, peOffset, data.size())) {
        std::cerr << "[-] Not enough space in PE headers for new section header.\n";
        return false;
    }

    IMAGE_SECTION_HEADER newSec = {};
    memcpy(newSec.Name, ".msgbox", 7);
    newSec.VirtualAddress = newRVA;
    newSec.PointerToRawData = newRaw;
    newSec.Misc.VirtualSize = 0x1000;
    newSec.SizeOfRawData = 0x1000;
    newSec.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    memcpy(&sections[nt->FileHeader.NumberOfSections], &newSec, sizeof(newSec));
    nt->FileHeader.NumberOfSections++;
    opt->SizeOfImage = newSec.VirtualAddress + newSec.Misc.VirtualSize;

    if (newRaw + 0x1000 > data.max_size()) {
        std::cerr << "[-] File too large after resizing.\n";
        return false;
    }

    data.resize(newRaw + 0x1000, 0x00);

    DWORD originalEP = opt->AddressOfEntryPoint;

    BYTE patch[sizeof(shellcode32)];
    memcpy(patch, shellcode32, sizeof(shellcode32));

    const char* msg = "Hello from 32-bit MessageBoxA";
    const char* cap = "Injected!";
    DWORD msgOffset = newRaw + 0x100;
    DWORD capOffset = msgOffset + strlen(msg) + 1;

    std::memcpy(&data[msgOffset], msg, strlen(msg) + 1);
    std::memcpy(&data[capOffset], cap, strlen(cap) + 1);

    HMODULE user32 = LoadLibraryA("user32.dll");
    FARPROC msgbox = GetProcAddress(user32, "MessageBoxA");
    if (!msgbox) {
        std::cerr << "[-] Failed to resolve MessageBoxA.\n";
        return false;
    }

    *(DWORD*)(patch + 3) = opt->ImageBase + newSec.VirtualAddress + 0x100 + strlen(msg) + 1;
    *(DWORD*)(patch + 8) = opt->ImageBase + newSec.VirtualAddress + 0x100;
    *(DWORD*)(patch + 13) = (DWORD)(DWORD_PTR)msgbox;
    *(DWORD*)(patch + 17) = originalEP - newSec.VirtualAddress - sizeof(shellcode32);

    memcpy(&data[newRaw], patch, sizeof(patch));
    opt->AddressOfEntryPoint = newSec.VirtualAddress;

    return true;
}
#pragma endregion

bool patcher::patch_pe(const std::string& filename)

{
    std::ifstream in(filename, std::ios::binary);
    if (!in) return false;
    std::vector<char> data((std::istreambuf_iterator<char>(in)), {});
    in.close();

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] Invalid MZ signature.\n";
        return false;
    }

    DWORD peOffset = dos->e_lfanew;
    DWORD sig = *(DWORD*)&data[peOffset];
    if (sig != IMAGE_NT_SIGNATURE) {
        std::cerr << "[-] Invalid PE signature.\n";
        return false;
    }

    WORD machine = *(WORD*)&data[peOffset + 4];
    bool is64 = (machine == IMAGE_FILE_MACHINE_AMD64);

    if (is64)
    {
        std::cout << "[*] 64-bit PE detected.\n";
        // 1. finding enough free space in .text
        bool status = patch_x64_add_to_text();
        if (status)
        {
            // 2. adding a new section if not enough space in .text
            status = patch_x64_add_new_section(data, peOffset);
            if (!status) {
                std::cout << "[*] unable to create patched pe file.\n";
                return;
            }
        }
    }
    else
    {
        std::cout << "[*] 32-bit PE detected.\n";
        // 1. finding enough free space in .text
        bool status = patch_x86_add_to_text();
        if (!status)
        {
            // 2. adding a new section if not enough space in .text
            status = patch_x86_add_new_section(data, peOffset);
            if (!status) {
                std::cout << "[*] unable to create patched pe file.\n";
                return;
            }
        }
    }

    std::ofstream out("patched.exe", std::ios::binary);
    out.write(data.data(), data.size());
    out.close();

    std::cout << "[+] Patched file written to patched.exe\n";
    return true;
}