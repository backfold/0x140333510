
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined4 * FUN_1402b18c0(undefined4 *param_1,longlong *param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined8 *puVar8;
  ulonglong uVar9;
  undefined1 auStack_88 [32];
  undefined4 local_68;
  undefined1 local_60 [16];
  undefined4 *local_50;
  undefined1 local_48 [16];
  ulonglong local_38;
  
  local_38 = DAT_1403eef38 ^ (ulonglong)auStack_88;
  local_68 = 0;
  *param_1 = 0;
  *(undefined8 *)(param_1 + 6) = 0;
  *(undefined8 *)(param_1 + 8) = 0;
  *(undefined8 *)(param_1 + 10) = 0;
  local_50 = param_1;
  FUN_140294900(param_1 + 0xc);
  FUN_140294900(param_1 + 0x10);
  FUN_140294900(param_1 + 0x14);
  local_68 = 1;
  uVar4 = FUN_140290a60(param_2);
  *param_1 = uVar4;
  uVar4 = FUN_140290a60(param_2);
  param_1[1] = uVar4;
  uVar4 = FUN_140290a60(param_2);
  param_1[2] = uVar4;
  uVar4 = FUN_140290a60(param_2);
  param_1[3] = uVar4;
  uVar4 = FUN_140290a60(param_2);
  param_1[4] = uVar4;
  uVar4 = FUN_140290a60(param_2);
  param_1[5] = uVar4;
  uVar5 = FUN_140290a60(param_2);
  if (uVar5 != 0) {
    uVar9 = (ulonglong)uVar5;
    do {
      (**(code **)(*param_2 + 0x48))(param_2,local_48,0x10);
      puVar6 = (undefined4 *)FUN_1402948d0(local_60,local_48);
      puVar7 = *(undefined4 **)(param_1 + 8);
      if (puVar7 == *(undefined4 **)(param_1 + 10)) {
        FUN_1402b1170(param_1 + 6,puVar7,puVar6);
      }
      else {
        uVar4 = puVar6[1];
        uVar1 = puVar6[2];
        uVar2 = puVar6[3];
        *puVar7 = *puVar6;
        puVar7[1] = uVar4;
        puVar7[2] = uVar1;
        puVar7[3] = uVar2;
        *(longlong *)(param_1 + 8) = *(longlong *)(param_1 + 8) + 0x10;
      }
      uVar9 = uVar9 - 1;
    } while (uVar9 != 0);
  }
  (**(code **)(*param_2 + 0x48))(param_2,local_48,0x10);
  puVar7 = (undefined4 *)FUN_1402948d0(local_60,local_48);
  uVar4 = puVar7[1];
  uVar1 = puVar7[2];
  uVar2 = puVar7[3];
  param_1[0xc] = *puVar7;
  param_1[0xd] = uVar4;
  param_1[0xe] = uVar1;
  param_1[0xf] = uVar2;
  if ((*(byte *)(param_1 + 1) & 0x10) != 0) {
    (**(code **)(*param_2 + 0x48))(param_2,local_48,0x10);
    puVar7 = (undefined4 *)FUN_1402948d0(local_60,local_48);
    uVar4 = puVar7[1];
    uVar1 = puVar7[2];
    uVar2 = puVar7[3];
    param_1[0x10] = *puVar7;
    param_1[0x11] = uVar4;
    param_1[0x12] = uVar1;
    param_1[0x13] = uVar2;
    (**(code **)(*param_2 + 0x48))(param_2,local_48,0x10);
    puVar8 = (undefined8 *)FUN_1402948d0(local_60,local_48);
    uVar3 = puVar8[1];
    *(undefined8 *)(param_1 + 0x14) = *puVar8;
    *(undefined8 *)(param_1 + 0x16) = uVar3;
  }
  return param_1;
}

