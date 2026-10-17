
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

void FUN_1402aa3d0(undefined8 *param_1)

{
  longlong lVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 *puVar6;
  undefined1 auStack_158 [32];
  undefined8 local_138;
  ulonglong local_130;
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
  
  local_10 = DAT_1403eef38 ^ (ulonglong)auStack_158;
  puVar6 = param_1;
  if (7 < (ulonglong)param_1[3]) {
    puVar6 = (undefined8 *)*param_1;
  }
  local_128 = 0;
  local_130 = local_130 & 0xffffffff00000000;
  local_138._0_4_ = 3;
  lVar1 = (*(code *)0x3d591a)(puVar6,0x80000000,1,0);
  param_1[0x1c] = lVar1;
  if (lVar1 == -1) {
    FUN_14002f780(local_58,&DAT_140354950);
    uVar2 = FUN_1402717c0(local_118,L"Exception",0,0x30);
    uVar3 = FUN_1402a8770(local_108,L"Lambda::PackageLoader::OpenFile",0,0x30);
    uVar4 = FUN_1402a8780(local_f8,L"C:\\Git\\lapacker\\lib\\FileSystemLib\\PackageLoader.cpp",0,
                          0x30);
    uVar5 = FUN_1402717a0(local_e8,&DAT_140333668,0,0x30);
    local_138 = uVar3;
    uVar3 = FUN_140276320(local_d8,0x37,uVar5,uVar4);
    uVar2 = FUN_140276270(local_a0,uVar3,uVar2);
    FUN_1402a0290(local_38,uVar2,2,local_58);
                    /* WARNING: Subroutine does not return */
    FUN_1402b8f9b(local_38,&DAT_1403d3758);
  }
  local_130 = 0;
  local_138 = (ulonglong)local_138._4_4_ << 0x20;
  lVar1 = (*(code *)0x3d85ca)(lVar1,0,2,0);
  param_1[0x1d] = lVar1;
  if (lVar1 == 0) {
    FUN_14002f780(local_58,&DAT_140354950);
    uVar2 = FUN_1402717c0(local_e8,L"Exception",0,0x30);
    uVar3 = FUN_1402a8770(local_f8,L"Lambda::PackageLoader::OpenFile",0,0x30);
    uVar4 = FUN_1402a8780(local_108,L"C:\\Git\\lapacker\\lib\\FileSystemLib\\PackageLoader.cpp",0,
                          0x30);
    uVar5 = FUN_1402717a0(local_118,&DAT_140333670,0,0x30);
    local_138 = uVar3;
    uVar3 = FUN_140276320(local_d8,0x3d,uVar5,uVar4);
    uVar2 = FUN_140276270(local_a0,uVar3,uVar2);
    FUN_1402a0290(local_38,uVar2,3,local_58);
                    /* WARNING: Subroutine does not return */
    FUN_1402b8f9b(local_38,&DAT_1403d3758);
  }
  local_138 = 0;
  lVar1 = (*(code *)0x3d59ee)(lVar1,4,0,0);
  param_1[0x1e] = lVar1;
  if (lVar1 != 0) {
    return;
  }
  FUN_14002f780(local_58,&DAT_140354950);
  uVar2 = FUN_1402717c0(local_e8,L"Exception",0,0x30);
  uVar3 = FUN_1402a8770(local_f8,L"Lambda::PackageLoader::OpenFile",0,0x30);
  uVar4 = FUN_1402a8780(local_108,L"C:\\Git\\lapacker\\lib\\FileSystemLib\\PackageLoader.cpp",0,0x30
                       );
  uVar5 = FUN_1402717a0(local_118,&DAT_140333678,0,0x30);
  local_138 = uVar3;
  uVar3 = FUN_140276320(local_d8,0x43,uVar5,uVar4);
  uVar2 = FUN_140276270(local_a0,uVar3,uVar2);
  FUN_1402a0290(local_38,uVar2,4,local_58);
                    /* WARNING: Subroutine does not return */
  FUN_1402b8f9b(local_38,&DAT_1403d3758);
}


