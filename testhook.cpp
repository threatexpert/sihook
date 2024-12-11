#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ws2tcpip.h>
#include <Windows.h>

extern "C" {
#include "sihook/hook.h"
}

typedef
int
WINAPI
typedef_MessageBoxExA(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType,
    WORD wLanguageId);

typedef_MessageBoxExA * org_MessageBoxExA = NULL;

int
WINAPI
myMessageBoxExA(
     HWND hWnd,
     LPCSTR lpText,
     LPCSTR lpCaption,
     UINT uType,
     WORD wLanguageId)
{
    return org_MessageBoxExA(hWnd, "hooked", lpCaption, uType, wLanguageId);
}


int main()
{
    int n;
	n = sihook_create(MessageBoxExA, -1, myMessageBoxExA, (void**)&org_MessageBoxExA);

    sihook_enable(org_MessageBoxExA, 1);

	MessageBoxExA(0, "will be replaced to 'hooked'", "sihook", MB_ICONINFORMATION, 0);

    sihook_free(org_MessageBoxExA);

    MessageBoxExA(0, "test-free", "sihook", MB_ICONINFORMATION, 0);

}
