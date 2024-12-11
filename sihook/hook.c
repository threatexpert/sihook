#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif
#define _LDASM_EXT_X86_TABLE
#include "ldasm/x86_ldasm.h"
#include "ldasm/x86_ldasm_precompiled.h"

struct HookContext {
    unsigned char callorig[64];
    int origasm_len;
    unsigned char jmper[64];
    int jmpsize;
    char* target;
    char* hooker;
    int enabled;
};

#if defined(_WIN32) || defined(_WIN64)

typedef int (__stdcall *x86_ldasm_stdcall_t)(void*, unsigned int, unsigned char*);

static
int ch_mem_rwe(void* target, int len, int w)
{
    DWORD pro;
    if (w) {
        if (VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &pro) && FlushInstructionCache(GetCurrentProcess(), target, len)) {
            return 0;
        }
    }
    else {
        if (VirtualProtect(target, len, PAGE_EXECUTE_READ, &pro) && FlushInstructionCache(GetCurrentProcess(), target, len)) {
            return 0;
        }
    }

    return -1;
}

static
int write_code(void* target, void* data, int len)
{
    SIZE_T w;
    if (WriteProcessMemory(GetCurrentProcess(), target, data, len, &w) && FlushInstructionCache(GetCurrentProcess(), target, len)) {
        return 0;
    }
    else {
        return -1;
    }
}

#else

static
size_t get_page_size() {
    return sysconf(_SC_PAGESIZE);
}

static
void* align_address(void* addr, size_t page_size) {
    return (void*)((uintptr_t)addr & ~((uintptr_t)page_size - 1));
}

static
size_t align_length(void* addr, size_t len, size_t page_size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + len;
    end = (end + page_size - 1) & ~((uintptr_t)page_size - 1);
    return end - (uintptr_t)align_address(addr, page_size);
}

static
int ch_mem_rwe(void* addr, size_t len, int w) {
    size_t page_size = get_page_size();
    void* aligned_addr = align_address(addr, page_size);
    size_t aligned_len = align_length(addr, len, page_size);

    if (w) {
        return mprotect(aligned_addr, aligned_len, PROT_READ | PROT_WRITE | PROT_EXEC);
    }
    else {
        return mprotect(aligned_addr, aligned_len, PROT_READ | PROT_EXEC);
    }
}

static
int write_code(void* target, void* data, int len)
{
    ch_mem_rwe(target, len, 1);
    memcpy(target, data, len);
    return 0;
}

#endif

static
int createjmp_x86_64(void* from, void* to, unsigned char* out)
{
#if defined(__x86_64__) || defined(_M_X64)
    int need;
    int64_t offset = (int64_t)from - ((int64_t)to + 5);
    if (offset < -0x7fffffff || offset > 0x7fffffff) {
        need = 14;
        out[0] = 0xff;
        out[1] = 0x25;
        out[2] = 0;
        out[3] = 0;
        out[4] = 0;
        out[5] = 0;
        *(uint64_t*)&out[6] = (uint64_t)to;
    }
    else {
        need = 5;
        out[0] = 0xe9;
        *(uint32_t*)&out[1] = (uint32_t)((char*)to - (char*)from - 5);
    }
    return need;
#else
    return -1;
#endif
}

static
int hook_needed_x86_64(void* target, int jmpsize)
{
#if defined(__x86_64__) || defined(_M_X64)
    int fsize = 64;
    int j = 0;
    unsigned char* code = (unsigned char*)target;
    x86_dasm_context_t x86_dctx;
    memset(&x86_dctx, 0, sizeof(x86_dctx));
    x86_dctx.dmode = X86_DMODE_64BIT;

#if defined(_WIN32) || defined(_WIN64)
    ch_mem_rwe(x86_ldasm_win64_nodata_bin, sizeof(x86_ldasm_win64_nodata_bin), 1);
#else
    ch_mem_rwe(x86_ldasm_lin64_bin, sizeof(x86_ldasm_lin64_bin), 1);
#endif

    while (j < fsize)
    {
#if defined(_WIN32) || defined(_WIN64)
        x86_ldasm_stdcall_t x86_ldasm_pre = (x86_ldasm_stdcall_t)x86_ldasm_win64_nodata_bin;
#else
        x86_ldasm_t x86_ldasm_pre = (x86_ldasm_t)x86_ldasm_lin64_bin;
#endif

        int len = x86_ldasm_pre(&x86_dctx, x86_dctx.dmode, &code[j]);

        if (len < 0)
        {
            break;
        }
        else
        {
            j += x86_dctx.len;
            if (j >= jmpsize) {
                return j;
            }
        }
    }
#endif
    return -1;
}

static
int hook_create_x86_64(void* target, int target_codelen, void* hooker, void** hookhandle)
{
    struct HookContext* hctx = (struct HookContext*)malloc((sizeof(struct HookContext) + 4096 - 1) & ~(4096-1));
    if (!hctx) {
        return -1;
    }
    memset(hctx, 0, sizeof(*hctx));
    hctx->jmpsize = createjmp_x86_64(target, hooker, hctx->jmper);
    if (target_codelen == -1) {
        target_codelen = hook_needed_x86_64(target, hctx->jmpsize);
    }
    if (target_codelen < 0) {
        return target_codelen;
    }
    if (target_codelen < hctx->jmpsize) {
        return -2;
    }
    hctx->target = target;
    hctx->hooker = hooker;
    memset(hctx->callorig, 0x90, sizeof(hctx->callorig));
    hctx->origasm_len = target_codelen;
    memcpy(hctx->callorig, target, hctx->origasm_len);
    createjmp_x86_64(hctx->callorig + hctx->origasm_len, hctx->target + hctx->origasm_len, hctx->callorig + hctx->origasm_len);

    ch_mem_rwe(hctx->callorig, sizeof(hctx->callorig), 1);
    *hookhandle = hctx;
    return 0;
}


static
int createjmp_x86(void* from, void* to, unsigned char* out)
{
    int need;
    need = 5;
    out[0] = 0xe9;
    *(uint32_t*)&out[1] = (uint32_t)((char*)to - (char*)from - 5);
    return need;
}

static
int hook_needed_x86(void* target, int jmpsize)
{
#if defined(__i386) || defined(_M_IX86)

    int fsize = 64;
    int j = 0;
    unsigned char* code = (unsigned char*)target;
    x86_dasm_context_t x86_dctx;
    memset(&x86_dctx, 0, sizeof(x86_dctx));
    x86_dctx.dmode = X86_DMODE_32BIT;

#if defined(_WIN32)
    ch_mem_rwe(x86_ldasm_win32_nodata_bin, sizeof(x86_ldasm_win32_nodata_bin), 1);
#else
    ch_mem_rwe(x86_ldasm_lin32_bin, sizeof(x86_ldasm_lin32_bin), 1);
#endif

    while (j < fsize)
    {
#if defined(_WIN32)
        x86_ldasm_stdcall_t x86_ldasm_pre = (x86_ldasm_stdcall_t)x86_ldasm_win32_nodata_bin;
#else
        x86_ldasm_t x86_ldasm_pre = (x86_ldasm_t)x86_ldasm_lin32_bin;
#endif
        int len = x86_ldasm_pre(&x86_dctx, x86_dctx.dmode, &code[j]);

        if (len < 0)
        {
            break;
        }
        else
        {
            j += x86_dctx.len;
            if (j >= jmpsize) {
                return j;
            }
        }
    }
#endif
    return -1;
}

static
int hook_create_x86(void* target, int target_codelen, void* hooker, void** hookhandle)
{
    struct HookContext* hctx = (struct HookContext*)malloc((sizeof(struct HookContext) + 4096 - 1) & ~(4096-1));
    if (!hctx) {
        return -1;
    }
    memset(hctx, 0, sizeof(*hctx));
    hctx->jmpsize = createjmp_x86(target, hooker, hctx->jmper);
    if (target_codelen == -1) {
        target_codelen = hook_needed_x86(target, hctx->jmpsize);
    }
    if (target_codelen < 0) {
        return target_codelen;
    }
    if (target_codelen < hctx->jmpsize) {
        return -2;
    }
    hctx->target = target;
    hctx->hooker = hooker;
    memset(hctx->callorig, 0x90, sizeof(hctx->callorig));
    hctx->origasm_len = target_codelen;
    memcpy(hctx->callorig, target, hctx->origasm_len);
    createjmp_x86(hctx->callorig + hctx->origasm_len, hctx->target + hctx->origasm_len, hctx->callorig + hctx->origasm_len);

    ch_mem_rwe(hctx->callorig, sizeof(hctx->callorig), 1);
    *hookhandle = hctx;
    return 0;
}


int sihook_create(void* target, int target_codelen, void* hooker, void** hookhandle)
{
#if defined(__x86_64__) || defined(_M_X64)
    return hook_create_x86_64(target, target_codelen, hooker, hookhandle);
#elif defined(__i386) || defined(_M_IX86)
    return hook_create_x86(target, target_codelen, hooker, hookhandle);
#else
#error "arch not supported"
#endif
}

int sihook_enable(void* hookhandle, int enable)
{
    int ret = -101;
    struct HookContext* hctx = (struct HookContext*)hookhandle;
    if (enable) {
        if (!hctx->enabled) {
            ret = write_code(hctx->target, hctx->jmper, hctx->jmpsize);
            if (ret == 0) {
                hctx->enabled = 1;
                return 0;
            }
        }
    }
    else {
        if (hctx->enabled) {
            ret = write_code(hctx->target, hctx->callorig, hctx->origasm_len);
            if (ret == 0) {
                hctx->enabled = 0;
                return 0;
            }
        }
    }
    return ret;
}

void sihook_free(void* hookhandle)
{
    struct HookContext* hctx = (struct HookContext*)hookhandle;
    if (hctx->enabled) {
        sihook_enable(hctx, 0);
    }
    free(hctx);
}
