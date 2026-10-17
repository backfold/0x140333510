
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

longlong *
FUN_14029ba50(longlong *param_1,undefined8 param_2,undefined8 param_3,undefined1 param_4,
             undefined1 param_5,undefined4 param_6,undefined4 param_7)

{
  char cVar1;
  longlong lVar2;
  longlong lVar3;
  longlong *plVar4;
  longlong lVar5;
  code *pcVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  void *pvVar9;
  undefined8 uVar10;
  void *pvVar11;
  longlong *plVar12;
  undefined8 *puVar13;
  longlong lVar14;
  ulonglong uVar15;
  undefined8 *puVar16;
  longlong *plVar17;
  bool bVar18;
  undefined1 auStack_1d8 [32];
  undefined4 *local_1b8;
  uint local_1a8;
  undefined4 local_1a4;
  longlong *local_1a0;
  longlong *local_198;
  longlong *local_190;
  longlong *local_188;
  longlong *local_180;
  longlong lStack_178;
  ulonglong local_170;
  undefined1 local_168 [248];
  undefined4 local_70;
  ulonglong local_58;
  
  local_58 = DAT_1403eef38 ^ (ulonglong)auStack_1d8;
  pvVar11 = (void *)0x0;
  local_1a8 = 0;
  local_1a4 = 0;
  local_190 = param_1;
  FUN_1402a8e70(local_168);
  FUN_1402aa3d0(local_168);
  local_1b8 = &local_1a4;
  FUN_1402aa700(local_168,param_4,param_6,param_7);
  pvVar9 = operator_new(0x80);
  bVar18 = pvVar9 != (void *)0x0;
  if (bVar18) {
    local_1a0 = pvVar9;
    uVar10 = FUN_14029d6b0(local_168,&local_188);
    local_1a8 = 1;
    FUN_1400612f0(pvVar9,uVar10);
    *(undefined4 *)((longlong)pvVar9 + 0x20) = local_70;
    *(undefined8 *)((longlong)pvVar9 + 0x28) = 0;
    *(undefined8 *)((longlong)pvVar9 + 0x30) = 0;
    *(undefined8 *)((longlong)pvVar9 + 0x38) = 0;
    puVar13 = (undefined8 *)((longlong)pvVar9 + 0x40);
    *puVar13 = 0;
    *(undefined8 *)((longlong)pvVar9 + 0x48) = 0;
    local_198 = puVar13;
    pvVar11 = operator_new(0xa0);
    *(void **)pvVar11 = pvVar11;
    *(void **)((longlong)pvVar11 + 8) = pvVar11;
    *(void **)((longlong)pvVar11 + 0x10) = pvVar11;
    *(undefined2 *)((longlong)pvVar11 + 0x18) = 0x101;
    *puVar13 = pvVar11;
    *(undefined8 *)((longlong)pvVar9 + 0x50) = 0;
    *(undefined8 *)((longlong)pvVar9 + 0x60) = 0;
    *(undefined8 *)((longlong)pvVar9 + 0x68) = 7;
    *(undefined2 *)((longlong)pvVar9 + 0x50) = 0;
    *(undefined4 *)((longlong)pvVar9 + 0x70) = 0;
    *(undefined2 *)((longlong)pvVar9 + 0x74) = 0;
    *(undefined1 *)((longlong)pvVar9 + 0x76) = 0;
    *(undefined8 *)((longlong)pvVar9 + 0x78) = 0;
    pvVar11 = pvVar9;
  }
  plVar12 = (longlong *)0x0;
  *param_1 = 0;
  param_1[1] = 0;
  local_1a0 = pvVar11;
  local_198 = operator_new(0x18);
  if (local_198 != (longlong *)0x0) {
    *local_198 = 0;
    local_198[1] = 0;
    *(undefined4 *)(local_198 + 1) = 1;
    *(undefined4 *)((longlong)local_198 + 0xc) = 1;
    *local_198 = (longlong)std::_Ref_count<Lambda::Package>::vftable;
    local_198[2] = (longlong)pvVar11;
    plVar12 = local_198;
  }
  *param_1 = (longlong)pvVar11;
  param_1[1] = (longlong)plVar12;
  local_1a0 = (longlong *)0x0;
  local_1a8 = bVar18 | 2;
  if (bVar18) {
    local_1a8 = 2;
    if (7 < local_170) {
      uVar15 = local_170 * 2 + 2;
      plVar12 = local_188;
      if (0xfff < uVar15) {
        uVar15 = local_170 * 2 + 0x29;
        plVar12 = (longlong *)local_188[-1];
        if (0x1f < (ulonglong)((longlong)local_188 + (-8 - (longlong)plVar12))) {
          (*(code *)0x3d7636)();
          pcVar6 = (code *)swi(3);
          plVar12 = (longlong *)(*pcVar6)();
          return plVar12;
        }
      }
      thunk_FUN_1402b909d(plVar12,uVar15);
    }
    lStack_178 = 0;
    local_170 = 7;
    local_188 = (longlong *)((ulonglong)local_188 & 0xffffffffffff0000);
  }
  puVar13 = (undefined8 *)FUN_1402aaef0(local_168,&local_188);
  lVar2 = *param_1;
  puVar16 = (undefined8 *)(lVar2 + 0x28);
  if (puVar16 != puVar13) {
    FUN_14029e2d0(puVar16);
    *puVar16 = *puVar13;
    *(undefined8 *)(lVar2 + 0x30) = puVar13[1];
    *(undefined8 *)(lVar2 + 0x38) = puVar13[2];
    *puVar13 = 0;
    puVar13[1] = 0;
    puVar13[2] = 0;
  }
  plVar12 = local_188;
  if (local_188 != (longlong *)0x0) {
    for (; local_1a0 = plVar12, plVar12 != local_180; plVar12 = plVar12 + 4) {
      FUN_14002f8c0(plVar12);
    }
    uVar15 = lStack_178 - (longlong)local_188 & 0xffffffffffffffe0;
    plVar12 = local_188;
    if (0xfff < uVar15) {
      uVar15 = uVar15 + 0x27;
      plVar12 = (longlong *)local_188[-1];
      if (0x1f < (ulonglong)((longlong)local_188 + (-8 - (longlong)plVar12))) {
        (*(code *)0x3d7636)();
        pcVar6 = (code *)swi(3);
        plVar12 = (longlong *)(*pcVar6)();
        return plVar12;
      }
    }
    thunk_FUN_1402b909d(plVar12,uVar15);
    local_188 = (longlong *)0x0;
    local_180 = (longlong *)0x0;
    lStack_178 = 0;
  }
  plVar12 = (longlong *)FUN_1402aad60(local_168,&local_188);
  lVar2 = *param_1;
  plVar17 = (longlong *)(lVar2 + 0x40);
  if (plVar17 != plVar12) {
    lVar3 = *plVar17;
    FUN_14029a480(plVar17,plVar17,*(undefined8 *)(lVar3 + 8));
    *(longlong *)(lVar3 + 8) = lVar3;
    *(longlong *)lVar3 = lVar3;
    *(longlong *)(lVar3 + 0x10) = lVar3;
    *(undefined8 *)(lVar2 + 0x48) = 0;
    lVar3 = *plVar17;
    *plVar17 = *plVar12;
    *plVar12 = lVar3;
    lVar3 = *(longlong *)(lVar2 + 0x48);
    *(longlong *)(lVar2 + 0x48) = plVar12[1];
    plVar12[1] = lVar3;
  }
  cVar1 = *(char *)(local_188[1] + 0x19);
  plVar12 = (longlong *)local_188[1];
  while (cVar1 == '\0') {
    FUN_14029a480(&local_188,&local_188,plVar12[2]);
    plVar4 = (longlong *)*plVar12;
    plVar17 = plVar12 + 4;
    local_198 = plVar17;
    FUN_14029b530(plVar12 + 8);
    local_1a0 = plVar17;
    FUN_14002f8c0(plVar17);
    thunk_FUN_1402b909d(plVar12,0xa0);
    plVar12 = plVar4;
    cVar1 = *(char *)((longlong)plVar4 + 0x19);
  }
  thunk_FUN_1402b909d(local_188,0xa0);
  plVar12 = (longlong *)FUN_14029fbf0(param_3,&local_188);
  lVar2 = *param_1;
  plVar17 = (longlong *)(lVar2 + 0x50);
  if (plVar17 != plVar12) {
    if (7 < *(ulonglong *)(lVar2 + 0x68)) {
      lVar5 = *plVar17;
      lVar3 = *(ulonglong *)(lVar2 + 0x68) * 2;
      lVar14 = lVar5;
      if (0xfff < lVar3 + 2U) {
        lVar14 = *(longlong *)(lVar5 + -8);
        if (0x1f < (lVar5 - lVar14) - 8U) {
          (*(code *)0x3d7636)(lVar5 - lVar14,lVar3 + 0x29);
          pcVar6 = (code *)swi(3);
          plVar12 = (longlong *)(*pcVar6)();
          return plVar12;
        }
      }
      thunk_FUN_1402b909d(lVar14);
    }
    *(undefined8 *)(lVar2 + 0x60) = 0;
    *(undefined8 *)(lVar2 + 0x68) = 7;
    *(undefined2 *)plVar17 = 0;
    uVar7 = *(undefined4 *)((longlong)plVar12 + 4);
    lVar3 = plVar12[1];
    uVar8 = *(undefined4 *)((longlong)plVar12 + 0xc);
    *(int *)plVar17 = (int)*plVar12;
    *(undefined4 *)(lVar2 + 0x54) = uVar7;
    *(int *)(lVar2 + 0x58) = (int)lVar3;
    *(undefined4 *)(lVar2 + 0x5c) = uVar8;
    lVar3 = plVar12[3];
    *(longlong *)(lVar2 + 0x60) = plVar12[2];
    *(longlong *)(lVar2 + 0x68) = lVar3;
    plVar12[2] = 0;
    plVar12[3] = 7;
    *(undefined2 *)plVar12 = 0;
  }
  if (7 < local_170) {
    uVar15 = local_170 * 2 + 2;
    plVar12 = local_188;
    if (0xfff < uVar15) {
      uVar15 = local_170 * 2 + 0x29;
      plVar12 = (longlong *)local_188[-1];
      if (0x1f < (ulonglong)((longlong)local_188 + (-8 - (longlong)plVar12))) {
        (*(code *)0x3d7636)();
        pcVar6 = (code *)swi(3);
        plVar12 = (longlong *)(*pcVar6)();
        return plVar12;
      }
    }
    thunk_FUN_1402b909d(plVar12,uVar15);
  }
  lStack_178 = 0;
  local_170 = 7;
  local_188 = (longlong *)((ulonglong)local_188 & 0xffffffffffff0000);
  *(undefined1 *)(*param_1 + 0x74) = param_4;
  *(undefined1 *)(*param_1 + 0x75) = param_5;
  *(undefined4 *)(*param_1 + 0x78) = param_6;
  *(undefined4 *)(*param_1 + 0x7c) = param_7;
  if (*(char *)(*param_1 + 0x74) != '\0') {
    *(undefined4 *)(*param_1 + 0x70) = local_1a4;
  }
  FUN_1402a9490(local_168);
  return param_1;
}


