dotnet publish -c Release -r linux-x64 /p:TrimmerRootAssembly=true /p:TrimmerScanAssemblyFiles=true /p:PublishSingleFile=true -p:PublishAot=false -o build_linux_x64
call cleanup