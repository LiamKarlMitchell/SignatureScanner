# Signature Scanner

I wanted a nicer signiture scanner that worked the way I wanted. Include however you want in your own DLL project.

<center>Video about Signiture Scanning

[![IMAGE ALT TEXT HERE](http://img.youtube.com/vi/WmHDQzfELxk/0.jpg)](http://www.youtube.com/watch?v=WmHDQzfELxk)

  - Easily find addresses.
  - Pulls out an address using XXXXXXXX
  - Magic
  
</center>

This project was previously on google code here: https://code.google.com/p/signiturescanner/ but github is nicer.

> You can search with a ? for wildcard or XXXXXXXX where there is an address you want back. This can be usefull for finding code to hook,detour,modify or memory pointers in code that you want.
> When making signitures you use wildcards to represent things that may change when recompiled, such as addresses.
> Returns NULL if not found

--- Example Usage:

Init
````
signature_scanner* sig = new signature_scanner();
````

Get a memory address in code at XXXXXXXX with wildcards.
````
DWORD_PTR address = signature_scanner->search("3AB2DFAB????????3FBACD300200A1XXXXXXXXB1C4DA");
````

Find Second instance 90/NOP
````
DWORD_PTR address = signiture_scanner->search("90");
if (address!=NULL)
{
address = signiture_scanner->search("90",0,true,address)
if (address!=NULL)
{
// Found it at address
}
else
{
// Not found 2nd time
}
}
else
{
// Found first time
}
````

Finding Text
````
DWORD_PTR address = signiture_scanner->search_text("Hello World");
````


There is also a find_all method.
This is useful for game memory modification in multiple areas.
For example the developers have a ``MOV EAX, [ECX+WeaponID*4], DEC EAX, MOV [ECX+WeaponID*4], EAX`` that decreases ammo but it is copy pasted to every function for every weapon's shoot. *Like in Quake 1, 2, 3 etc*.

You could NOP all of them. Or detour them all to only NOP for your player ID.

Do what you want license, IDGAF~