# ExecRemoteAssembly
Execute Remote Assembly with args passing and with AMSI and ETW patching  

1 - the ExecRemoteAssembly is created only to run .NET assemblies , that are based on C#.  
2 - the ExecRemoteAssembly accept URI of type :    
https://domain.name/PathToUri  
http://domain.name/PathToUri  
[https/http]://ip:port/pathtoUri  
[https/http]://ip/pathtoUri   

![ExecAMSI](https://user-images.githubusercontent.com/110354855/190879568-2f8587a6-59f8-4d4f-8954-cbeea472c5e2.png)

![IP](https://user-images.githubusercontent.com/110354855/198319100-a1235ba4-e761-4805-b169-4a880e39faa5.png)

![ipPort](https://user-images.githubusercontent.com/110354855/198319234-132c214a-2863-4a7e-9906-a7409d11b3d9.png)

# Build

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" ExecRemoteNET.sln /p:Configuration=Release /p:Platform=x64 /verbosity:minimal
```

# Credits
https://github.com/mez-0/InMemoryNET  
This is an improved version of this project that supports AMSI & ETW patching and URI parsing
