
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

void FUN_1402a95f0(longlong *param_1)

{
  char cVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined1 auStack_148 [32];
  undefined8 local_128;
  undefined1 local_118 [16];
  undefined1 local_108 [16];
  undefined1 local_f8 [16];
  undefined1 local_e8 [16];
  undefined1 local_d8 [56];
  undefined1 local_a0 [72];
  undefined1 local_58 [32];
  undefined1 local_38 [40];
  ulonglong local_10;
  
  local_10 = DAT_1403eef38 ^ (ulonglong)auStack_148;
  (**(code **)(*(longlong *)*param_1 + 0x20))();
  param_1 = (longlong *)*param_1;
  iVar2 = FUN_1402b17f0(param_1);
  if ((int)param_1[6] != iVar2) {
    FUN_14002f780(local_58,&DAT_140354950);
    uVar3 = FUN_1402717c0(local_118,L"Exception",0,0x30);
    uVar4 = FUN_14028a5e0(local_108,L"Lambda::PackageHeaderLoader::LoadEncryptData",0,0x30);
    uVar5 = FUN_1402a8780(local_f8,L"C:\\Git\\lapacker\\lib\\FileSystemLib\\PackageLoader.cpp",0,
                          0x30);
    uVar6 = FUN_1402717b0(local_e8,&DAT_140333740,0,0x30);
    local_128 = uVar4;
    uVar4 = FUN_140276320(local_d8,0xae,uVar6,uVar5);
    uVar3 = FUN_140276270(local_a0,uVar4,uVar3);
    FUN_1402a0290(local_38,uVar3,5,local_58);
                    /* WARNING: Subroutine does not return */
    FUN_1402b8f9b(local_38,&DAT_1403d3758);
  }
  cVar1 = (**(code **)(*param_1 + 0x10))(param_1);
  if (cVar1 != '\0') {
    return;
  }
  FUN_14002f780(local_58,&DAT_140354950);
  uVar3 = FUN_1402717c0(local_e8,L"Exception",0,0x30);
  uVar4 = FUN_14028a5e0(local_f8,L"Lambda::PackageHeaderLoader::LoadEncryptData",0,0x30);
  uVar5 = FUN_1402a8780(local_108,L"C:\\Git\\lapacker\\lib\\FileSystemLib\\PackageLoader.cpp",0,0x30
                       );
  uVar6 = FUN_1402717b0(local_118,&DAT_140333748,0,0x30);
  local_128 = uVar4;
  uVar4 = FUN_140276320(local_d8,0xb3,uVar6,uVar5);
  uVar3 = FUN_140276270(local_a0,uVar4,uVar3);
  FUN_1402a0290(local_38,uVar3,6,local_58);
                    /* WARNING: Subroutine does not return */
  FUN_1402b8f9b(local_38,&DAT_1403d3758);
}


