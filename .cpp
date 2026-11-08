// Minecraft.Windows.exe — Bedrock 1.21.62 — x64 MSVC
// standalone DLL — manual map via your loader
// zeroes block placement delay via sig scan + float patch
// no CRT, no imports beyond kernel32 — safe for most manual mappers

#include <Windows.h>
#include <cstdint>
#include <cstring>

// ── sig scanner ────────────────────────────────────────────────────────────
static uintptr_t SigScan(uintptr_t base, size_t size,
                          const uint8_t* pat, const char* mask) {
    size_t len = strlen(mask);
    for (size_t i = 0; i < size - len; ++i) {
        bool found = true;
        for (size_t j = 0; j < len; ++j) {
            if (mask[j] == 'x' && ((uint8_t*)(base + i))[j] != pat[j]) {
                found = false;
                break;
            }
        }
        if (found) return base + i;
    }
    return 0;
}

// ── resolve RIP-relative ptr from instruction ──────────────────────────────
// reads the 4-byte displacement at (addr+offset) and resolves to absolute ptr
static uintptr_t ResolveRip(uintptr_t addr, int disp_offset, int instr_len) {
    int32_t disp = *(int32_t*)(addr + disp_offset);
    return addr + instr_len + disp;
}

// ── patch helper ───────────────────────────────────────────────────────────
static void PatchFloat(uintptr_t ptr, float val) {
    DWORD old;
    VirtualProtect((void*)ptr, 4, PAGE_EXECUTE_READWRITE, &old);
    *(float*)ptr = val;
    VirtualProtect((void*)ptr, 4, old, &old);
}

// ── 1.21.62 signatures ────────────────────────────────────────────────────
//
// PlacementDelay float (0.2f default):
//   sig: F3 0F 10 05 ?? ?? ?? ?? F3 0F 5C C8
//   mask: xxxx????xxxx
//   disp at +4, instr_len = 8  →  resolves to the float itself
//
// InteractDelay float (right-click items, 0.1f default):
//   sig: F3 0F 10 0D ?? ?? ?? ?? 0F 2F C8
//   mask: xxxx????xxx
//   disp at +4, instr_len = 8

static const uint8_t kPlacePat[]  = { 0xF3,0x0F,0x10,0x05,0x00,0x00,0x00,0x00,0xF3,0x0F,0x5C,0xC8 };
static const char    kPlaceMask[] = "xxxx????xxxx";

static const uint8_t kInteractPat[]  = { 0xF3,0x0F,0x10,0x0D,0x00,0x00,0x00,0x00,0x0F,0x2F,0xC8 };
static const char    kInteractMask[] = "xxxx????xxx";

// ── get module size from PE header ─────────────────────────────────────────
static size_t ModuleSize(uintptr_t base) {
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    return nt->OptionalHeader.SizeOfImage;
}

// ── main patch routine ─────────────────────────────────────────────────────
static void ApplyPatches() {
    uintptr_t base = (uintptr_t)GetModuleHandleA("Minecraft.Windows.exe");
    if (!base) return;
    size_t sz = ModuleSize(base);

    // block placement delay → 0.0f
    uintptr_t place_insn = SigScan(base, sz, kPlacePat, kPlaceMask);
    if (place_insn) {
        uintptr_t place_ptr = ResolveRip(place_insn, 4, 8);
        PatchFloat(place_ptr, 0.0f);
    }

    // interact/item delay → 0.0f (covers rod, bucket, food, bow draw reset)
    uintptr_t interact_insn = SigScan(base, sz, kInteractPat, kInteractMask);
    if (interact_insn) {
        uintptr_t interact_ptr = ResolveRip(interact_insn, 4, 8);
        PatchFloat(interact_ptr, 0.0f);
    }
}

// ── restore on unload ──────────────────────────────────────────────────────
static void RestorePatches() {
    uintptr_t base = (uintptr_t)GetModuleHandleA("Minecraft.Windows.exe");
    if (!base) return;
    size_t sz = ModuleSize(base);

    uintptr_t place_insn = SigScan(base, sz, kPlacePat, kPlaceMask);
    if (place_insn) PatchFloat(ResolveRip(place_insn, 4, 8), 0.2f);

    uintptr_t interact_insn = SigScan(base, sz, kInteractPat, kInteractMask);
    if (interact_insn) PatchFloat(ResolveRip(interact_insn, 4, 8), 0.1f);
}

// ── DllMain ────────────────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            ApplyPatches();
            break;
        case DLL_PROCESS_DETACH:
            RestorePatches();
            break;
    }
    return TRUE;
}