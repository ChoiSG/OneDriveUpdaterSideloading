# OneDriveUpdater DLL Sideloading 
This repo contains source code for DLL sideloading the `version.dll` for OneDriveUpdater.exe/OneDriveStandaloneUpdater.exe. 
The payload is based on the subroutines outlined in the PaloAltoNetworks Unit42's [blog post](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/). 

My blog post regarding this payload: https://blog.sunggwanchoi.com/recreating-an-iso-payload-for-fun-and-no-profit/

## version 
Modified source code from the proxy DLL created by [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) from [Flangvik](https://twitter.com/Flangvik).

## versionConsole 
A console version of the above used for debugging purposes. Already contains a messagebox shellcode.

## Credits 
- [PaloAltoNetworks Unit42](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)
- [Peperunas](https://twitter.com/peperunas)'s [injectopi](https://github.com/peperunas/injectopi/tree/master/CreateSection)
- [Sektor7's RTO Malware Essential Course](https://institute.sektor7.net/red-team-operator-malware-development-essentials)
- [mgeeky](https://twitter.com/mariuszbit)'s [PackMyPayload](https://github.com/mgeeky/PackMyPayload)
- [Flangvik](https://twitter.com/Flangvik)'s [SharpDllProxy](https://github.com/Flangvik/SharpDllProxy)
