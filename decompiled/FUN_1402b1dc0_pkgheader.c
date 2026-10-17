
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

ulonglong FUN_1402b1d40(longlong param_1,undefined8 *param_2,undefined8 *param_3)

{
  undefined8 *puVar1;
  code *pcVar2;
  undefined1 auVar3 [16];
  uint uVar4;
  uint uVar5;
  ulonglong uVar6;
  __uint64 _Var7;
  void *pvVar8;
  longlong lVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  undefined1 auStack_888 [32];
  undefined8 local_868;
  undefined4 uStack_860;
  undefined4 uStack_85c;
  undefined8 local_858;
  ulonglong uStack_850;
  undefined2 local_848 [1024];
  ulonglong local_48;
  
  local_48 = DAT_1403eef38 ^ (ulonglong)auStack_888;
  uVar4 = FUN_140290a60(*param_2);
  *(uint *)(param_1 + 0xc) = uVar4;
  if ((char *)param_3[1] == (char *)*param_3) {
                    /* WARNING: Subroutine does not return */
    FUN_1402ab5f0();
  }
  uVar4 = (int)*(char *)*param_3 ^ uVar4;
  uVar6 = (ulonglong)uVar4;
  uVar11 = uVar6 * 2;
  uVar5 = (**(code **)(*(longlong *)*param_2 + 8))();
  if (uVar11 < uVar5) {
    if (uVar4 < 0x400) {
      (**(code **)(*(longlong *)*param_2 + 0x48))((longlong *)*param_2,local_848,uVar4 * 2);
      if (0x7ff < uVar11) {
                    /* WARNING: Subroutine does not return */
        FUN_140263f8c();
      }
      local_848[uVar6] = 0;
      local_858 = 0;
      uStack_850 = 7;
      local_868 = 0;
      FUN_14002f970(&local_868,local_848,uVar4);
      FUN_14005ef10(param_1 + 0x10,&local_868);
      if (7 < uStack_850) {
        uVar11 = uStack_850 * 2 + 2;
        lVar9 = local_868;
        if (0xfff < uVar11) {
          uVar11 = uStack_850 * 2 + 0x29;
          lVar9 = *(longlong *)(local_868 + -8);
          if (0x1f < (local_868 - lVar9) - 8) {
            (*(code *)0x3d7636)();
            pcVar2 = (code *)swi(3);
            uVar11 = (*pcVar2)();
            return uVar11;
          }
        }
        thunk_FUN_1402b909d(lVar9,uVar11);
      }
    }
    else {
      auVar3 = ZEXT816(2) * ZEXT416(uVar4 + 1);
      _Var7 = auVar3._0_8_;
      if (auVar3._8_8_ != 0) {
        _Var7 = 0xffffffffffffffff;
      }
      pvVar8 = operator_new(_Var7);
      (**(code **)(*(longlong *)*param_2 + 0x48))((longlong *)*param_2,pvVar8,uVar4 * 2);
      *(undefined2 *)(uVar11 + (longlong)pvVar8) = 0;
      local_858 = 0;
      uStack_850 = 7;
      local_868 = 0;
      FUN_14002f970(&local_868,pvVar8,uVar4);
      puVar1 = (undefined8 *)(param_1 + 0x10);
      if (puVar1 != &local_868) {
        FUN_14002f8c0(puVar1);
        *(undefined4 *)puVar1 = (undefined4)local_868;
        *(undefined4 *)(param_1 + 0x14) = local_868._4_4_;
        *(undefined4 *)(param_1 + 0x18) = uStack_860;
        *(undefined4 *)(param_1 + 0x1c) = uStack_85c;
        *(undefined8 *)(param_1 + 0x20) = local_858;
        *(ulonglong *)(param_1 + 0x28) = uStack_850;
        local_858 = 0;
        uStack_850 = 7;
        local_868 = local_868 & 0xffffffffffff0000;
      }
      if (7 < uStack_850) {
        uVar11 = uStack_850 * 2 + 2;
        uVar10 = local_868;
        if (0xfff < uVar11) {
          uVar11 = uStack_850 * 2 + 0x29;
          uVar10 = *(ulonglong *)(local_868 - 8);
          if (0x1f < (local_868 - uVar10) - 8) {
            (*(code *)0x3d7636)();
            pcVar2 = (code *)swi(3);
            uVar11 = (*pcVar2)();
            return uVar11;
          }
        }
        thunk_FUN_1402b909d(uVar10,uVar11);
      }
      local_858 = 0;
      uStack_850 = 7;
      local_868 = local_868 & 0xffffffffffff0000;
      thunk_FUN_1402b909d(pvVar8);
    }
  }
  else {
    uVar6 = 0;
  }
  return uVar6;
}


