del C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\*.sys
del C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\encrypt.png

"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\NickolasZhao\YSN.sln" /rebuild Release   /project  C:\DriverCodes\HideDriver\NickolasZhao\SSS_Drivers\SSS_Drivers.vcxproj  



cd C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\



AutoBuild.exe



del C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\SSS_Drivers.*



"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\NickolasZhao\YSN.sln" /build Release   /project  C:\DriverCodes\HideDriver\NickolasZhao\ProxyDrv\ProxyDrv.vcxproj



cd "C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\"

ClearPEdbg.exe



del C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\ProxyDrv.*
del C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\encrypt.png

C:\ProgramFiles\DSigntool\CSignTool.exe sign /r dandan /f C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\ProxyDrv_nodbg.sys /ac /kp /s

ren ProxyDrv_nodbg.sys ProxyDrv.sys

cd "C:\DriverCodes\HideDriver\NickolasZhao\x64\Release\"

ClearPEdbg.exe