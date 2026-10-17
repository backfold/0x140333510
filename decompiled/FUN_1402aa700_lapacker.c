
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

void FUN_1402aa700(longlong param_1,undefined8 param_2,undefined4 param_3,int param_4,
                  undefined4 *param_5)

{
  int *piVar1;
  longlong *plVar2;
  int iVar3;
  longlong *plVar4;
  longlong *plVar5;
  code *pcVar6;
  longlong lVar7;
  undefined4 uVar8;
  uint uVar9;
  int iVar10;
  undefined8 *puVar11;
  undefined4 *puVar12;
  ulonglong uVar13;
  longlong lVar14;
  undefined4 local_res18 [4];
  undefined1 auStack_4b8 [32];
  undefined4 local_498;
  undefined4 local_490;
  undefined4 local_488;
  uint local_478;
  uint local_474;
  undefined8 local_470;
  longlong *plStack_468;
  undefined8 local_458;
  longlong *plStack_450;
  longlong *local_448;
  longlong *plStack_440;
  undefined ***local_438;
  undefined ***local_430;
  undefined8 local_428;
  longlong *plStack_420;
  longlong *local_418;
  longlong *plStack_410;
  undefined1 local_408 [8];
  longlong *local_400;
  undefined1 local_3f8 [8];
  longlong *local_3f0;
  undefined1 local_3e8 [8];
  longlong *local_3e0;
  undefined **local_3d8;
  undefined1 local_3d0 [184];
  int local_318;
  undefined **local_310;
  undefined1 local_308 [184];
  int local_250;
  undefined1 local_248 [96];
  undefined1 local_1e8 [96];
  undefined2 local_188;
  undefined2 uStack_186;
  undefined4 uStack_184;
  undefined4 uStack_180;
  undefined4 uStack_17c;
  undefined8 local_178;
  ulonglong uStack_170;
  undefined2 local_168;
  undefined6 uStack_166;
  undefined8 local_158;
  ulonglong local_150;
  undefined1 local_148 [128];
  undefined1 local_c8 [128];
  ulonglong local_48;
  
  local_48 = DAT_1403eef38 ^ (ulonglong)auStack_4b8;
  local_res18[0] = param_3;
  local_478 = FUN_14029fa20(param_1 + 0x20);
  local_474 = FUN_14029f920(param_1 + 0x20);
  FUN_14002f780(&local_188,&DAT_140354950);
  puVar11 = (undefined8 *)FUN_1402b2480(local_408,*(undefined8 *)(param_1 + 0xf0),0x7fffffff);
  local_470 = *puVar11;
  plStack_468 = (longlong *)puVar11[1];
  *puVar11 = 0;
  puVar11[1] = 0;
  if (local_400 != (longlong *)0x0) {
    LOCK();
    plVar4 = local_400 + 1;
    lVar14 = *plVar4;
    *(int *)plVar4 = (int)*plVar4 + -1;
    UNLOCK();
    if ((int)lVar14 == 1) {
      (**(code **)*local_400)(local_400);
      LOCK();
      piVar1 = (int *)((longlong)local_400 + 0xc);
      iVar10 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar10 == 1) {
        (**(code **)(*local_400 + 8))(local_400);
      }
    }
  }
  puVar12 = (undefined4 *)
            FUN_1402a9fc0(*(undefined8 *)(param_1 + 0x100),&local_168,&local_470,&local_478);
  if ((undefined4 *)&local_188 != puVar12) {
    FUN_14002f8c0(&local_188);
    uStack_184 = puVar12[1];
    uStack_180 = puVar12[2];
    uStack_17c = puVar12[3];
    local_188 = (undefined2)*puVar12;
    uStack_186 = (undefined2)((uint)*puVar12 >> 0x10);
    local_178 = *(undefined8 *)(puVar12 + 4);
    uStack_170 = *(ulonglong *)(puVar12 + 6);
    *(undefined8 *)(puVar12 + 4) = 0;
    *(undefined8 *)(puVar12 + 6) = 7;
    *(undefined2 *)puVar12 = 0;
  }
  if (7 < local_150) {
    uVar13 = local_150 * 2 + 2;
    lVar7 = CONCAT62(uStack_166,local_168);
    lVar14 = lVar7;
    if (0xfff < uVar13) {
      uVar13 = local_150 * 2 + 0x29;
      lVar14 = *(longlong *)(lVar7 + -8);
      if (0x1f < (lVar7 - lVar14) - 8U) {
        (*(code *)0x3d7636)();
        pcVar6 = (code *)swi(3);
        (*pcVar6)();
        return;
      }
    }
    thunk_FUN_1402b909d(lVar14,uVar13);
  }
  local_158 = 0;
  local_150 = 7;
  local_168 = 0;
  uVar8 = FUN_1402a8630(&local_188);
  plVar4 = plStack_468;
  *param_5 = uVar8;
  if (plStack_468 != (longlong *)0x0) {
    LOCK();
    plVar5 = plStack_468 + 1;
    lVar14 = *plVar5;
    *(int *)plVar5 = (int)*plVar5 + -1;
    UNLOCK();
    if ((int)lVar14 == 1) {
      (**(code **)*plStack_468)(plStack_468);
      LOCK();
      piVar1 = (int *)((longlong)plVar4 + 0xc);
      iVar10 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar10 == 1) {
        (**(code **)(*plVar4 + 8))(plVar4);
      }
    }
  }
  uVar9 = (*(code *)**(undefined8 **)**(undefined8 **)(param_1 + 0x100))();
  lVar14 = (ulonglong)uVar9 + (ulonglong)local_478 + *(longlong *)(param_1 + 0xf0);
  FUN_14029f470(param_1 + 0x20,local_148,&local_188);
  puVar11 = (undefined8 *)FUN_1402b2480(local_3f8,lVar14,0x7fffffff);
  local_458 = *puVar11;
  plVar4 = (longlong *)puVar11[1];
  *puVar11 = 0;
  puVar11[1] = 0;
  plStack_450 = plVar4;
  if (local_3f0 != (longlong *)0x0) {
    LOCK();
    plVar5 = local_3f0 + 1;
    lVar7 = *plVar5;
    *(int *)plVar5 = (int)*plVar5 + -1;
    UNLOCK();
    if ((int)lVar7 == 1) {
      (**(code **)*local_3f0)(local_3f0);
      LOCK();
      piVar1 = (int *)((longlong)local_3f0 + 0xc);
      iVar10 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar10 == 1) {
        (**(code **)(*local_3f0 + 8))(local_3f0);
      }
    }
  }
  local_438 = &local_3d8;
  local_430 = (undefined ***)&local_428;
  local_3d8 = Lambda::SnowCipher::vftable;
  local_488 = 0;
  local_490 = 0;
  local_498 = 0;
  FUN_1402abee0(local_3d0,local_148,0x80,0);
  iVar10 = (int)(param_4 + (param_4 >> 0x1f & 3U)) >> 2;
  local_318 = iVar10;
  FUN_1402ace20(local_3d0,iVar10);
  if (plVar4 != (longlong *)0x0) {
    LOCK();
    *(int *)(plVar4 + 1) = (int)plVar4[1] + 1;
    UNLOCK();
  }
  local_428 = local_458;
  plStack_420 = plStack_450;
  FUN_14029aba0(local_248,&local_428,&local_3d8,0);
  FUN_1402a95f0(*(undefined8 *)(param_1 + 0x100),local_248);
  FUN_14029ae30(local_248);
  if (plStack_450 != (longlong *)0x0) {
    LOCK();
    plVar5 = plVar4 + 1;
    lVar7 = *plVar5;
    *(int *)plVar5 = (int)*plVar5 + -1;
    UNLOCK();
    if ((int)lVar7 == 1) {
      (**(code **)*plVar4)(plVar4);
      LOCK();
      piVar1 = (int *)((longlong)plVar4 + 0xc);
      iVar3 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar3 == 1) {
        (**(code **)(*plVar4 + 8))(plVar4);
      }
    }
  }
  uVar9 = (**(code **)(*(longlong *)**(undefined8 **)(param_1 + 0x100) + 8))();
  lVar14 = (ulonglong)local_474 + (ulonglong)uVar9 + lVar14;
  FUN_14029f6b0(param_1 + 0x20,local_c8,&local_188);
  puVar11 = (undefined8 *)FUN_1402b2480(local_3e8,lVar14,0x7fffffff);
  plVar4 = (longlong *)*puVar11;
  plVar5 = (longlong *)puVar11[1];
  *puVar11 = 0;
  puVar11[1] = 0;
  local_448 = plVar4;
  plStack_440 = plVar5;
  if (local_3e0 != (longlong *)0x0) {
    LOCK();
    plVar2 = local_3e0 + 1;
    lVar7 = *plVar2;
    *(int *)plVar2 = (int)*plVar2 + -1;
    UNLOCK();
    if ((int)lVar7 == 1) {
      (**(code **)*local_3e0)(local_3e0);
      LOCK();
      piVar1 = (int *)((longlong)local_3e0 + 0xc);
      iVar3 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar3 == 1) {
        (**(code **)(*local_3e0 + 8))(local_3e0);
      }
    }
  }
  local_430 = &local_310;
  local_438 = (undefined ***)&local_418;
  local_310 = Lambda::SnowCipher::vftable;
  local_488 = 0;
  local_490 = 0;
  local_498 = 0;
  FUN_1402abee0(local_308,local_c8,0x80,0);
  local_250 = iVar10;
  FUN_1402ace20(local_308,iVar10);
  if (plVar5 != (longlong *)0x0) {
    LOCK();
    *(int *)(plVar5 + 1) = (int)plVar5[1] + 1;
    UNLOCK();
  }
  local_418 = local_448;
  plStack_410 = plStack_440;
  FUN_14029aba0(local_1e8,&local_418,&local_310,0);
  FUN_1402a9820(*(undefined8 *)(param_1 + 0x100),local_1e8,local_res18);
  iVar10 = (**(code **)(*plVar4 + 0x20))(plVar4);
  *(int *)(param_1 + 0xf8) = ((int)lVar14 - *(int *)(param_1 + 0xf0)) + iVar10;
  FUN_14029ae30(local_1e8);
  if (plStack_440 != (longlong *)0x0) {
    LOCK();
    plVar4 = plVar5 + 1;
    lVar14 = *plVar4;
    *(int *)plVar4 = (int)*plVar4 + -1;
    UNLOCK();
    if ((int)lVar14 == 1) {
      (**(code **)*plVar5)(plVar5);
      LOCK();
      piVar1 = (int *)((longlong)plVar5 + 0xc);
      iVar10 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar10 == 1) {
        (**(code **)(*plVar5 + 8))(plVar5);
      }
    }
  }
  uVar9 = *(uint *)(param_1 + 0xf8) & 0x3ff;
  if (uVar9 != 0) {
    *(uint *)(param_1 + 0xf8) = (*(uint *)(param_1 + 0xf8) - uVar9) + 0x400;
  }
  if (7 < uStack_170) {
    uVar13 = uStack_170 * 2 + 2;
    lVar7 = CONCAT44(uStack_184,CONCAT22(uStack_186,local_188));
    lVar14 = lVar7;
    if (0xfff < uVar13) {
      uVar13 = uStack_170 * 2 + 0x29;
      lVar14 = *(longlong *)(lVar7 + -8);
      if (0x1f < (lVar7 - lVar14) - 8U) {
        (*(code *)0x3d7636)();
        pcVar6 = (code *)swi(3);
        (*pcVar6)();
        return;
      }
    }
    thunk_FUN_1402b909d(lVar14,uVar13);
  }
  return;
}


