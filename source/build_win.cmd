dotnet publish -o build_win_x64\
upx "build_win_x64\PE-LiteScan.exe" --lzma --best
call cleanup