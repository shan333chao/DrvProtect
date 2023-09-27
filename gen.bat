
"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\驱动隐藏\驱动隐藏.sln" /rebuild Release   /project  C:\DriverCodes\HideDriver\驱动隐藏\SSS_Drivers\SSS_Drivers.vcxproj  

pause

cd C:\DriverCodes\HideDriver\驱动隐藏\x64\Release\

pause

AutoBuild.exe

pause

del C:\DriverCodes\HideDriver\驱动隐藏\x64\Release\SSS_Drivers.*

pause

"C:\ProgramFiles (x86)\VisualStudio\2019\Community\Common7\IDE\devenv.com"  "C:\DriverCodes\HideDriver\驱动隐藏\驱动隐藏.sln" /build Release   /project  C:\DriverCodes\HideDriver\驱动隐藏\ProxyDrv\ProxyDrv.vcxproj

pause

copy "C:\DriverCodes\HideDriver\驱动隐藏\x64\Release\ProxyDrv\ProxyDrv.sys" "C:\DriverCodes\HideDriver\驱动隐藏\x64\Release\ProxyDrv.sys"

pause

cd "C:\DriverCodes\HideDriver\驱动隐藏\x64\Release\"

ClearPEdbg.exe

pause

del C:\DriverCodes\HideDriver\驱动隐藏\x64\Release\ProxyDrv.*
del C:\DriverCodes\HideDriver\驱动隐藏\x64\Release\encrypt.png