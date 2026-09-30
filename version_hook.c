#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#pragma comment(linker, "/NODEFAULTLIB")
#pragma comment(linker, "/ENTRY:DllMain")
#pragma comment(linker, "/export:GetFileVersionInfoA=version_orig.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=version_orig.GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:GetFileVersionInfoExA=version_orig.GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=version_orig.GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=version_orig.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=version_orig.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=version_orig.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=version_orig.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=version_orig.GetFileVersionInfoW")
#pragma comment(linker, "/export:VerFindFileA=version_orig.VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=version_orig.VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=version_orig.VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=version_orig.VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=version_orig.VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=version_orig.VerLanguageNameW")
#pragma comment(linker, "/export:VerQueryValueA=version_orig.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=version_orig.VerQueryValueW")
#pragma function(memcpy, memset, memcmp)

#define HM_OODAG 0x50499749u

typedef struct {
    const wchar_t *mod;
    unsigned rva;
    unsigned char old[4];
    unsigned char new_[4];
    unsigned n;
} OD_PATCH;

static const OD_PATCH kPatches[] = {
    {L"OOSoftware.License.ClientLib.dll", 0x20E2u,
     {0x6E, 0x02, 0x02, 0x00}, {0x0A, 0x16, 0x2A, 0x00}, 3u},
    {L"OOSoftware.License.ClientLib.dll", 0x24B4u,
     {0x3E, 0x02, 0x28, 0x00}, {0x0A, 0x17, 0x2A, 0x00}, 3u},
    {L"OOSoftware.License.SharedLib.dll", 0x2401u,
     {0xDE, 0x02, 0x28, 0x00}, {0x0A, 0x17, 0x2A, 0x00}, 3u},
    {L"OOSoftware.License.SharedLib.dll", 0x2444u,
     {0x2A, 0x02, 0x28, 0x00}, {0x0A, 0x16, 0x2A, 0x00}, 3u},
    {L"OOSoftware.License.SharedLib.dll", 0x2300u,
     {0x1E, 0x02, 0x7B, 0x00}, {0x0A, 0x18, 0x2A, 0x00}, 3u},
    {L"OOSoftware.License.SharedLib.dll", 0x2311u,
     {0x1E, 0x02, 0x7B, 0x00}, {0x0A, 0x17, 0x2A, 0x00}, 3u},
    {L"OOSoftware.License.SharedLib.dll", 0x2322u,
     {0x1E, 0x02, 0x7B, 0x00}, {0x0A, 0x18, 0x2A, 0x00}, 3u},
    {L"OOSoftware.License.SharedLib.dll", 0x2439u,
     {0x2A, 0x02, 0x28, 0x00}, {0x0A, 0x17, 0x2A, 0x00}, 3u},
};

static HMODULE g_orig;
static volatile LONG g_done;

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--)
        *d++ = (unsigned char)c;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *p = (const unsigned char *)a;
    const unsigned char *q = (const unsigned char *)b;
    while (n--) {
        if (*p != *q)
            return (int)*p - (int)*q;
        p++;
        q++;
    }
    return 0;
}

static unsigned hmix(unsigned h, unsigned char b)
{
    h ^= (unsigned)b;
    h = ((h << 7) | (h >> 25)) + 0x6D2B79F5u;
    h ^= h >> 11;
    return h;
}

static unsigned h_wfnv(const wchar_t *s, unsigned nbytes)
{
    unsigned h = 0xA5A5C3E1u;
    unsigned n, i;
    if (!s || nbytes < 2)
        return 0;
    n = nbytes / 2u;
    for (i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)(s[i] & 0xFF);
        if (c >= 'A' && c <= 'Z')
            c = (unsigned char)(c + 32);
        h = hmix(h, c);
    }
    return h;
}

typedef struct _USTR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} USTR;

typedef struct _LDR {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    USTR FullDllName;
    USTR BaseDllName;
} LDR;

typedef struct _PEB_LDR {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR;

typedef struct _PEB {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR *Ldr;
} PEB;

static void *peb_ptr(void)
{
    return (void *)__readgsqword(0x60);
}

static unsigned host_exe_hash(void)
{
    PEB *peb = (PEB *)peb_ptr();
    LIST_ENTRY *head, *cur;
    LDR *e;
    if (!peb || !peb->Ldr)
        return 0;
    head = &peb->Ldr->InLoadOrderModuleList;
    cur = head->Flink;
    if (!cur || cur == head)
        return 0;
    e = (LDR *)cur;
    if (!e->BaseDllName.Buffer || e->BaseDllName.Length < 4)
        return 0;
    return h_wfnv(e->BaseDllName.Buffer, e->BaseDllName.Length);
}

static BYTE *find_module(const wchar_t *want)
{
    PEB *peb = (PEB *)peb_ptr();
    LIST_ENTRY *head, *cur;
    if (!peb || !peb->Ldr || !want)
        return 0;
    head = &peb->Ldr->InLoadOrderModuleList;
    cur = head->Flink;
    while (cur && cur != head) {
        LDR *e = (LDR *)cur;
        if (e->BaseDllName.Buffer && e->BaseDllName.Length >= 4) {
            unsigned n = e->BaseDllName.Length / 2u;
            unsigned i;
            int ok = 1;
            for (i = 0; want[i]; ++i) {
                wchar_t a = want[i];
                wchar_t b = e->BaseDllName.Buffer[i];
                if (a >= L'A' && a <= L'Z')
                    a = (wchar_t)(a + 32);
                if (b >= L'A' && b <= L'Z')
                    b = (wchar_t)(b + 32);
                if (i >= n || a != b) {
                    ok = 0;
                    break;
                }
            }
            if (ok)
                return (BYTE *)e->DllBase;
        }
        cur = cur->Flink;
    }
    return 0;
}

static int patch_bytes(BYTE *dst, const unsigned char *old, const unsigned char *new_, unsigned n)
{
    DWORD old_prot, tmp;
    if (!dst || !old || !new_ || !n)
        return 0;
    if (memcmp(dst, old, n) != 0 && memcmp(dst, new_, n) != 0)
        return 0;
    if (memcmp(dst, new_, n) == 0)
        return 1;
    if (!VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old_prot))
        return 0;
    memcpy(dst, new_, n);
    VirtualProtect(dst, n, old_prot, &tmp);
    FlushInstructionCache(GetCurrentProcess(), dst, n);
    return 1;
}

static void apply_unlock(void)
{
    unsigned i, ok, need;
    if (g_done)
        return;
    if (host_exe_hash() != HM_OODAG)
        return;
    ok = 0;
    need = (unsigned)(sizeof(kPatches) / sizeof(kPatches[0]));
    for (i = 0; i < need; ++i) {
        const OD_PATCH *p = &kPatches[i];
        BYTE *base = find_module(p->mod);
        if (!base)
            continue;
        if (patch_bytes(base + p->rva, p->old, p->new_, p->n))
            ok++;
    }
    if (ok == need)
        InterlockedExchange(&g_done, 1);
}

static DWORD WINAPI apply_later(LPVOID p)
{
    unsigned n = 0;
    (void)p;
    for (;;) {
        apply_unlock();
        if (g_done || ++n >= 240u)
            break;
        Sleep(50u);
    }
    return 0;
}

static wchar_t *find_last_slash(wchar_t *s)
{
    wchar_t *last = NULL;
    while (s && *s) {
        if (*s == L'\\')
            last = s;
        s++;
    }
    return last;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    wchar_t path[MAX_PATH];
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        if (GetModuleFileNameW(h, path, MAX_PATH)) {
            lstrcpyW(find_last_slash(path) + 1, L"version_orig.dll");
            g_orig = LoadLibraryW(path);
        }
        apply_unlock();
        if (!g_done)
            QueueUserWorkItem(apply_later, 0, WT_EXECUTELONGFUNCTION);
    } else if (reason == DLL_PROCESS_DETACH && g_orig) {
        FreeLibrary(g_orig);
        g_orig = NULL;
    }
    return TRUE;
}
