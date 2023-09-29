del C:\DriverCodes\HideDriver\NickolasZhao\x64\Debug\*.sys
del C:\DriverCodes\HideDriver\NickolasZhao\x64\Debug\ProxyDrv.*
 

"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\NickolasZhao\YSN.sln" /rebuild Debug   /project  C:\DriverCodes\HideDriver\NickolasZhao\SSS_Drivers\SSS_Drivers.vcxproj  



cd C:\DriverCodes\HideDriver\NickolasZhao\x64\Debug\



AutoBuild.exe



del C:\DriverCodes\HideDriver\NickolasZhao\x64\Debug\SSS_Drivers.*



"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\NickolasZhao\YSN.sln" /build Debug   /project  C:\DriverCodes\HideDriver\NickolasZhao\ProxyDrv\ProxyDrv.vcxproj


C:\ProgramFiles\DSigntool\CSignTool.exe sign /r dandan /f C:\DriverCodes\HideDriver\NickolasZhao\x64\Debug\ProxyDrv.sys /ac /kp /s

