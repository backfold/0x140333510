// Function: 0x1400bef00 (queried at 0x1400bef4a)
// REA evidence_id: ev_22e9a94bf997dc20cb4bf74418704399aea0839b6ce1d440b96907461444586f
// Source: suddenattack.exe (sha256 1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741)

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 FUN_1400bef00(void)

{
  int iVar1;
  undefined8 uVar2;
  char *pcVar3;
  undefined1 auStack_158 [32];
  undefined1 local_138 [16];
  undefined1 local_128 [272];
  ulonglong local_18;
  
  local_18 = DAT_1403eef38 ^ (ulonglong)auStack_158;
  FUN_1402b8fb3(local_128,0,0x104);
  local_138[0] = 0;
  *(undefined8 *)(DAT_1403fe648 + 0x32e0) = 0;
  *(undefined8 *)(DAT_1403fe648 + 0x32e8) = 0;
  *(undefined8 *)(DAT_1403fe648 + 0x32f0) = 0;
  iVar1 = FUN_1400bdc40("cshell.dll",local_128,0x104,local_138);
  if (iVar1 == 0) {
    iVar1 = FUN_140073ea0(local_128,local_138[0],DAT_1403fe648 + 0x32f0);
    if (iVar1 == 0) {
      FUN_1400bfea0("[MD5] CANTFIND_1");
      FUN_1400a94f0(DAT_1403fe648,0x1d,"cshell.dll");
      if (DAT_1403d99dc != 0) {
        (*(code *)0x3d5b28)();
      }
      if (0 < DAT_1403f91e4) {
        FUN_1400bfea0(DAT_1403d9848,"InitClientShellDE","LT_MISSINGSHELLDLL",&DAT_1403018f4);
      }
      return 0x1d;
    }
    if (DAT_140406160 == 0) {
      FUN_1400bfea0("[MD5] CANTFIND_2");
      FUN_1400a94f0(DAT_1403fe648,0x1e,"cshell.dll");
      if (DAT_1403d99dc != 0) {
        (*(code *)0x3d5b28)();
      }
      if (0 < DAT_1403f91e4) {
        pcVar3 = " ";
LAB_1400bf1bf:
        FUN_1400bfea0(DAT_1403d9848,"InitClientShellDE","LT_INVALIDSHELLDLL",pcVar3);
      }
    }
    else {
      FUN_1400bfea0("[MD5] setup dll");
      local_138[0] = 0;
      iVar1 = FUN_1400bdc40("cres.dll",local_128,0x104,local_138);
      if (iVar1 != 0) {
        FUN_1400bfea0("[MD5] CopyClientFile");
        FUN_1400a94f0(DAT_1403fe648,0x4c,"cres.dll");
        if (DAT_1403d99dc != 0) {
          (*(code *)0x3d5b28)();
        }
        if (0 < DAT_1403f91e4) {
          pcVar3 = "cres.dll";
          goto LAB_1400bf113;
        }
        goto LAB_1400bf12d;
      }
      iVar1 = FUN_140073ea0(local_128,local_138[0],DAT_1403fe648 + 0x32e0);
      if (iVar1 != 0) {
        if (DAT_140406168 != (longlong *)0x0) {
          FUN_1400bfea0("[MD5] instance_handle");
          (**(code **)(*DAT_140406168 + 8))(DAT_140406168,*(undefined8 *)(DAT_1403fe648 + 0x32f0));
        }
        FUN_1400bfea0("[MD5] Init");
        return 0;
      }
      FUN_1400bfea0("[MD5] CANTFIND_M");
      FUN_1400740f0(*(undefined8 *)(DAT_1403fe648 + 0x32f0));
      *(undefined8 *)(DAT_1403fe648 + 0x32f0) = 0;
      FUN_1400a94f0(DAT_1403fe648,0x1e,"cres.dll");
      if (DAT_1403d99dc != 0) {
        (*(code *)0x3d5b28)();
      }
      if (0 < DAT_1403f91e4) {
        pcVar3 = "cres.dll";
        goto LAB_1400bf1bf;
      }
    }
    uVar2 = 0x1e;
  }
  else {
    FUN_1400bfea0("[MD5] CopyClient");
    FUN_1400a94f0(DAT_1403fe648,0x4c,"cshell.dll");
    if (DAT_1403d99dc != 0) {
      (*(code *)0x3d5b28)();
    }
    if (0 < DAT_1403f91e4) {
      pcVar3 = "cshell.dll";
LAB_1400bf113:
      FUN_1400bfea0(DAT_1403d9848,"InitClientShellDE","LT_ERRORCOPYINGFILE",pcVar3);
    }
LAB_1400bf12d:
    uVar2 = 0x4c;
  }
  return uVar2;
}


