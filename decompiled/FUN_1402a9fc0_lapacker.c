
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 FUN_1402a9fc0(void **param_1,undefined8 param_2,undefined8 *param_3,uint *param_4)

{
  longlong lVar1;
  void *pvVar2;
  longlong lVar3;
  code *pcVar4;
  byte bVar5;
  int iVar6;
  void *pvVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  void *pvVar12;
  longlong lVar13;
  byte *pbVar14;
  ulonglong uVar15;
  uint uVar16;
  undefined1 auStack_1b8 [32];
  undefined8 local_198;
  byte local_188 [4];
  undefined4 local_184;
  byte *local_180;
  byte *local_178;
  byte *local_170;
  void *local_168 [2];
  void *local_158 [2];
  undefined8 local_148;
  undefined1 local_140 [16];
  undefined1 local_130 [16];
  undefined1 local_120 [56];
  undefined1 local_e8 [72];
  undefined1 local_a0 [32];
  undefined1 local_80 [40];
  ulonglong local_58;
  
  local_58 = DAT_1403eef38 ^ (ulonglong)auStack_1b8;
  pvVar7 = (void *)0x0;
  local_184 = 0;
  local_180 = (byte *)0x0;
  local_178 = (byte *)0x0;
  local_170 = (byte *)0x0;
  uVar16 = 0;
  local_148 = param_2;
  if (*param_4 != 0) {
    FUN_1402ab490(&local_180,*param_4);
    uVar16 = *param_4;
  }
  pvVar12 = pvVar7;
  if (uVar16 != 0) {
    do {
      local_188[0] = FUN_140290a30(*param_3);
      if (local_178 == local_170) {
        FUN_1402a8b40(&local_180,local_178,local_188);
      }
      else {
        *local_178 = local_188[0];
        local_178 = local_178 + 1;
      }
      uVar16 = (int)pvVar12 + 1;
      pvVar12 = (void *)(ulonglong)uVar16;
    } while (uVar16 < *param_4);
  }
  bVar5 = FUN_140290a00(*param_3);
  local_188[0] = bVar5;
  if (local_178 == local_180) {
LAB_1402aa3be:
                    /* WARNING: Subroutine does not return */
    FUN_1402ab5f0();
  }
  if ((byte)((char)*local_180 >> 1 ^ bVar5) == 3) {
    local_168[0] = operator_new(0x38);
    if (local_168[0] != (void *)0x0) {
      pvVar7 = (void *)FUN_1402b14d0(local_168[0]);
    }
    local_168[0] = (void *)0x0;
    local_184 = 2;
    pvVar12 = pvVar7;
    local_158[0] = pvVar7;
    if (param_1 != local_158) {
      pvVar12 = (void *)0x0;
      local_158[0] = (void *)0x0;
      pvVar2 = *param_1;
      *param_1 = pvVar7;
      bVar5 = local_188[0];
      if (pvVar2 != (void *)0x0) {
        local_168[0] = pvVar2;
        FUN_14002f8c0((longlong)pvVar2 + 0x10);
        thunk_FUN_1402b909d(pvVar2,0x38);
        bVar5 = local_188[0];
      }
    }
    local_184 = 0;
    if (pvVar12 != (void *)0x0) {
      local_168[0] = pvVar12;
      if (7 < *(ulonglong *)((longlong)pvVar12 + 0x28)) {
        lVar3 = *(longlong *)((longlong)pvVar12 + 0x10);
        lVar1 = *(ulonglong *)((longlong)pvVar12 + 0x28) * 2;
        lVar13 = lVar3;
        if (0xfff < lVar1 + 2U) {
          lVar13 = *(longlong *)(lVar3 + -8);
          if (0x1f < (lVar3 - lVar13) - 8U) {
            (*(code *)0x3d7636)(lVar3 - lVar13,lVar1 + 0x29);
            goto LAB_1402aa1d6;
          }
        }
        thunk_FUN_1402b909d(lVar13);
      }
      *(undefined8 *)((longlong)pvVar12 + 0x20) = 0;
      *(undefined8 *)((longlong)pvVar12 + 0x28) = 7;
      *(undefined2 *)((longlong)pvVar12 + 0x10) = 0;
      thunk_FUN_1402b909d(pvVar12,0x38);
    }
    *(byte *)((longlong)*param_1 + 8) = bVar5;
    uVar15 = 0;
    if (*param_4 != 0) {
      do {
        if ((ulonglong)((longlong)local_178 - (longlong)local_180) <= uVar15) goto LAB_1402aa3be;
        local_180[uVar15] = (char)local_180[uVar15] >> 1;
        uVar16 = (int)uVar15 + 1;
        uVar15 = (ulonglong)uVar16;
      } while (uVar16 < *param_4);
    }
  }
  else {
LAB_1402aa1d6:
    pvVar7 = (void *)0x0;
    local_168[0] = operator_new(0x38);
    if (local_168[0] != (void *)0x0) {
      pvVar7 = (void *)FUN_1402b1490();
    }
    local_168[0] = (void *)0x0;
    local_184 = 4;
    local_158[0] = (void *)0x0;
    pvVar12 = *param_1;
    *param_1 = pvVar7;
    if (pvVar12 != (void *)0x0) {
      local_168[0] = pvVar12;
      FUN_14002f8c0((longlong)pvVar12 + 0x10);
      thunk_FUN_1402b909d(pvVar12,0x38);
    }
    local_184 = 0;
    (**(code **)(*(longlong *)*param_3 + 0x28))((longlong *)*param_3,0xffffffff,1);
  }
  iVar6 = (**(code **)(*(longlong *)*param_1 + 0x18))(*param_1,param_3,&local_180);
  if (iVar6 == 0) {
    FUN_14002f780(local_a0,&DAT_140354950);
    uVar8 = FUN_1402717c0(local_168,L"Exception",0,0x30);
    uVar9 = FUN_14028a5d0(local_158,L"Lambda::PackageHeaderLoader::LoadMaskedData",0,0x30);
    uVar10 = FUN_1402a8780(local_140,L"C:\\Git\\lapacker\\lib\\FileSystemLib\\PackageLoader.cpp",0,
                           0x30);
    uVar11 = FUN_1402717b0(local_130,&DAT_1403336d8,0,0x30);
    local_198 = uVar9;
    uVar9 = FUN_140276320(local_120,0xa2,uVar11,uVar10);
    uVar8 = FUN_140276270(local_e8,uVar9,uVar8);
    FUN_1402a0290(local_80,uVar8,0x13,local_a0);
                    /* WARNING: Subroutine does not return */
    FUN_1402b8f9b(local_80,&DAT_1403d3758);
  }
  FUN_1402b1b50(*param_1,param_2,(longlong)*param_1 + 0x10,&local_180);
  local_184 = 1;
  if (local_180 != (byte *)0x0) {
    uVar15 = (longlong)local_170 - (longlong)local_180;
    pbVar14 = local_180;
    if (0xfff < uVar15) {
      uVar15 = uVar15 + 0x27;
      pbVar14 = *(byte **)(local_180 + -8);
      if ((byte *)0x1f < local_180 + (-8 - (longlong)pbVar14)) {
        (*(code *)0x3d7636)();
        pcVar4 = (code *)swi(3);
        uVar8 = (*pcVar4)();
        return uVar8;
      }
    }
    thunk_FUN_1402b909d(pbVar14,uVar15);
  }
  return param_2;
}


