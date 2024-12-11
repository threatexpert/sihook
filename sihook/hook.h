////
//// https://github.com/threatexpert/sihook
////

#pragma once



int sihook_create(void *target, int target_codelen, void *hooker, void **hookhandle);
int sihook_enable(void *hookhandle, int enable);
void sihook_free(void *hookhandle);

