#pragma once
#define DEBUG_MODULE 1
#if DEBUG_MODULE
#define Log( content, ... ) DbgPrintEx(77, 0, "[>] " content, __VA_ARGS__ )
#else
#define Log( content, ... )  
#endif  