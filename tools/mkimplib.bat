@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "C:\Discos\Proyectos\NEXCODE\DebuggerJ++\tools\keystone-win64\keystone-0.9.2-win64"
lib /nologo /def:keystone.def /machine:x64 /out:keystone_imp.lib
echo DONE %errorlevel%
