#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sihook/hook.h"

typedef void TARGET();
TARGET *org_target = NULL;

// Hooked function
void hooked_function() {
    printf("Function hooked!\n");

    org_target();
}

// Example function to be hooked
void target_function() {
    char buf[128] = "Original function called\n";
    printf("%s", buf); //演示被hook函数，这些写代码量多点，不然不够字节码放inlinehook
}

int main() {
    int ret;
    printf("Before hooking:\n");
    target_function();

    ret = sihook_create(target_function, -1, hooked_function, (void**)&org_target);
    if (ret != 0) {
        printf("err: sihook_create: %d\n", ret);
        return -1;
    }
    ret = sihook_enable(org_target, 1);
    if (ret != 0) {
        printf("err: sihook_enable: %d\n", ret);
        return -1;
    }

    printf("After hooking:\n");
    target_function();

    printf("free hook:\n");
    sihook_free(org_target);

    printf("After unhooking:\n");
    target_function();

    return 0;
}