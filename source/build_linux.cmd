dotnet publish -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true /p:PublishAot=false /p:PublishTrimmed=false /p:TrimMode=copyused -o build_linux_x64\
call cleanup