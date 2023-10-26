del C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\*.sys
del C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\encrypt.png

"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\NickolasZhao\YSN.sln" /Rebuild "Release|x64"   /project  C:\DriverCodes\HideDriver\NickolasZhao\SSS_Drivers\SSS_Drivers.vcxproj  



cd C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\



AutoBuild.exe



del C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\SSS_Drivers.*



"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\NickolasZhao\YSN.sln" /Rebuild "Release|x64"   /project  C:\DriverCodes\HideDriver\NickolasZhao\ProxyDrv\ProxyDrv.vcxproj



cd "C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\"

ClearPEdbg.exe



del C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\ProxyDrv.*
del C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\encrypt.png

C:\ProgramFiles\DSigntool\CSignTool.exe sign /r dandan /f C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\ProxyDrv_nodbg.sys /ac /kp /s

ren ProxyDrv_nodbg.sys ProxyDrv.sys

cd "C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\"

ClearPEdbg.exe


"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\NickolasZhao\YSN.sln" /Rebuild "Release|x64"  /project  C:\DriverCodes\HideDriver\NickolasZhao\DiviceClient\DiviceClient.vcxproj

"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\NickolasZhao\YSN.sln" /Rebuild "Release|x86"  /project  C:\DriverCodes\HideDriver\NickolasZhao\DiviceClient\DiviceClient.vcxproj

copy C:\DriverCodes\HideDriver\NickolasZhao\DiviceClient\driver_shellcode.h  C:\DriverCodes\HideDriver\NickolasZhao\SSS_dll

"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\NickolasZhao\YSN.sln" /Rebuild "Release|x64"  /project  C:\DriverCodes\HideDriver\NickolasZhao\SSS_dll\SSS_dll.vcxproj

"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\NickolasZhao\YSN.sln" /Rebuild "Release|x86"  /project  C:\DriverCodes\HideDriver\NickolasZhao\SSS_dll\SSS_dll.vcxproj

del /q C:\DriverCodes\HideDriver\NickolasZhao\out_put\*.*

copy C:\DriverCodes\HideDriver\NickolasZhao\Win32\Release\SSS_dll_x86.dll C:\DriverCodes\HideDriver\NickolasZhao\out_put
copy C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\SSS_dll_x64.dll C:\DriverCodes\HideDriver\NickolasZhao\out_put

