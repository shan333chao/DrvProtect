#pragma once
 
#ifdef _DEBUG_MODE
#define Log( content, ... ) DbgPrintEx(77, 0, "[>] " content, __VA_ARGS__ )
#else
#define Log( content, ... )  
#endif  