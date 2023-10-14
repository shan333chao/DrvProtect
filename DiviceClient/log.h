#pragma once
#include <Windows.h>
#define CRLF "\r\n"
#if defined(DISABLE_OUTPUT)
#define Logp(data, ...)
#else
#define Logp(text, ...) printf(text CRLF, __VA_ARGS__);
#endif