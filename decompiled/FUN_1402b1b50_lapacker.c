
undefined8 *
FUN_1402b1b50(undefined8 param_1,undefined8 *param_2,undefined8 *param_3,longlong *param_4)

{
  undefined8 uVar1;
  undefined1 auVar2 [16];
  __uint64 _Var3;
  void *pvVar4;
  undefined8 *puVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  void *pvVar8;
  void *pvVar9;
  uint uVar10;
  
  pvVar9 = (void *)0x0;
  auVar2._8_8_ = 0;
  auVar2._0_8_ = param_3[2];
  _Var3 = SUB168(ZEXT816(2) * auVar2,0);
  if (SUB168(ZEXT816(2) * auVar2,8) != 0) {
    _Var3 = 0xffffffffffffffff;
  }
  pvVar4 = operator_new(_Var3);
  pvVar8 = pvVar9;
  if (pvVar4 != (void *)0x0) {
    FUN_1402b8fb3(pvVar4,0,_Var3);
    pvVar8 = pvVar4;
  }
  pvVar4 = pvVar9;
  if (0 < *(int *)(param_3 + 2)) {
    do {
      if ((void *)param_3[2] <= pvVar9) {
                    /* WARNING: Subroutine does not return */
        FUN_14005fea0();
      }
      puVar5 = param_3;
      if (7 < (ulonglong)param_3[3]) {
        puVar5 = (undefined8 *)*param_3;
      }
      uVar6 = param_4[1] - *param_4;
      uVar7 = (ulonglong)(longlong)(int)pvVar4 % uVar6;
      if (uVar6 <= uVar7) {
                    /* WARNING: Subroutine does not return */
        FUN_1402ab5f0();
      }
      *(ushort *)((longlong)pvVar8 + (longlong)pvVar9 * 2) =
           (short)*(char *)(*param_4 + uVar7) ^ *(ushort *)((longlong)puVar5 + (longlong)pvVar9 * 2)
      ;
      uVar10 = (int)pvVar4 + 1;
      pvVar4 = (void *)(ulonglong)uVar10;
      pvVar9 = (void *)((longlong)pvVar9 + 1);
    } while ((int)uVar10 < *(int *)(param_3 + 2));
  }
  uVar1 = param_3[2];
  *param_2 = 0;
  param_2[2] = 0;
  param_2[3] = 7;
  *(undefined2 *)param_2 = 0;
  FUN_14002f970(param_2,pvVar8,uVar1,pvVar4,0,0,pvVar8);
  if (pvVar8 != (void *)0x0) {
    thunk_FUN_1402b909d(pvVar8);
  }
  return param_2;
}


