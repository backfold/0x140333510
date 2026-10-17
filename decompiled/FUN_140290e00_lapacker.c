
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 * FUN_140290e00(longlong *param_1,undefined8 *param_2)

{
  undefined1 auVar1 [16];
  ulonglong uVar2;
  __uint64 _Var3;
  void *pvVar4;
  undefined1 auStack_868 [32];
  undefined4 local_848;
  uint local_844;
  undefined8 *local_840;
  undefined2 local_838 [1024];
  ulonglong local_38;
  
  local_38 = DAT_1403eef38 ^ (ulonglong)auStack_868;
  *param_2 = 0;
  param_2[2] = 0;
  param_2[3] = 7;
  *(undefined2 *)param_2 = 0;
  local_848 = 1;
  local_840 = param_2;
  (**(code **)(*param_1 + 0x48))(param_1,&local_844,4);
  if (DAT_1403ef0bc < local_844) {
    FUN_14002f6f0(param_2,&DAT_140354950);
    DAT_14045fe44 = 1;
  }
  else {
    uVar2 = (ulonglong)local_844 * 2;
    if (local_844 < 0x400) {
      (**(code **)(*param_1 + 0x48))(param_1,local_838,local_844 * 2);
      if (0x7ff < uVar2) {
                    /* WARNING: Subroutine does not return */
        FUN_140263f8c();
      }
      local_838[local_844] = 0;
      FUN_14002f6f0(param_2,local_838);
    }
    else {
      auVar1 = ZEXT816(2) * ZEXT416(local_844 + 1);
      _Var3 = auVar1._0_8_;
      if (auVar1._8_8_ != 0) {
        _Var3 = 0xffffffffffffffff;
      }
      pvVar4 = operator_new(_Var3);
      (**(code **)(*param_1 + 0x48))(param_1,pvVar4,local_844 * 2);
      *(undefined2 *)(uVar2 + (longlong)pvVar4) = 0;
      FUN_14002f6f0(param_2,pvVar4);
      thunk_FUN_1402b909d(pvVar4);
    }
  }
  return param_2;
}

