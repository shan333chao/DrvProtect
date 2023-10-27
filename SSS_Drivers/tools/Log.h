#pragma once
#define CRLF " \r\n"
#define SKIP "   "

 
#ifdef _DEBUG_MODE
#define Log( content, ... ) DbgPrintEx(77, 0, "[>] " content  , __VA_ARGS__ )
#define Logf( content, ... ) DbgPrintEx(77, 0, "[>] " __FUNCTION__ content CRLF , __VA_ARGS__ ) 
#else
//#define Log( content, ... )  
//#define Logf( content, ... )
#define Log( content, ... ) DbgPrintEx(77, 0, "[>] " content  , __VA_ARGS__ )
#define Logf( content, ... ) DbgPrintEx(77, 0, "[>] " __FUNCTION__ SKIP content CRLF , __VA_ARGS__ ) 

#endif  