// REA session 28 — cshell.dll batch_decompile 0x0x180d5e2e0
// status: ok


/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 FUN_180d5e2e0(undefined8 param_1)

{
  void *pvVar1;
  void *pvVar2;
  undefined4 *puVar3;
  ulonglong uVar4;
  undefined1 auStack_88 [32];
  undefined8 local_68;
  undefined4 local_60;
  undefined4 uStack_5c;
  undefined4 uStack_58;
  undefined4 uStack_54;
  ulonglong local_50;
  ulonglong uStack_48;
  undefined8 local_40;
  undefined4 uStack_38;
  undefined4 uStack_34;
  ulonglong local_30;
  ulonglong uStack_28;
  undefined1 local_20 [8];
  ulonglong local_18;
  
  local_18 = DAT_1818e6cd8 ^ (ulonglong)auStack_88;
  FUN_18004ef00(&local_60,param_1);
  if (2 < local_50) {
    local_40 = 0;
    local_30 = 0;
    uStack_28 = 0xf;
    uVar4 = local_50 - 2;
    if (local_50 < local_50 - 2) {
      uVar4 = local_50;
    }
    puVar3 = &local_60;
    if (0xf < uStack_48) {
      puVar3 = (undefined4 *)CONCAT44(uStack_5c,local_60);
    }
    FUN_18004d940(&local_40,puVar3,uVar4);
    if (0xf < uStack_48) {
      pvVar1 = (void *)CONCAT44(uStack_5c,local_60);
      pvVar2 = pvVar1;
      if ((0xfff < uStack_48 + 1) &&
         (pvVar2 = *(void **)((longlong)pvVar1 + -8),
         0x1f < (ulonglong)((longlong)pvVar1 + (-8 - (longlong)pvVar2)))) {
                    /* WARNING: Subroutine does not return */
        _invalid_parameter_noinfo_noreturn();
      }
      free(pvVar2);
    }
    local_60 = (undefined4)local_40;
    uStack_5c = local_40._4_4_;
    uStack_58 = uStack_38;
    uStack_54 = uStack_34;
    local_50 = local_30;
    uStack_48 = uStack_28;
  }
  FUN_180d5e6c0(&local_60,local_20,8);
  FUN_180d5e9c0(local_20,&local_68);
  if (0xf < uStack_48) {
    pvVar1 = (void *)CONCAT44(uStack_5c,local_60);
    pvVar2 = pvVar1;
    if ((0xfff < uStack_48 + 1) &&
       (pvVar2 = *(void **)((longlong)pvVar1 + -8),
       0x1f < (ulonglong)((longlong)pvVar1 + (-8 - (longlong)pvVar2)))) {
                    /* WARNING: Subroutine does not return */
      _invalid_parameter_noinfo_noreturn();
    }
    free(pvVar2);
  }
  return local_68;
}


