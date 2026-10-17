
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

void FUN_14029f470(longlong param_1,longlong param_2,undefined8 *param_3)

{
  ulonglong uVar1;
  longlong lVar2;
  code *pcVar3;
  undefined8 ****ppppuVar4;
  undefined8 ***pppuVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  longlong *plVar8;
  undefined8 ****ppppuVar9;
  uint uVar10;
  ulonglong uVar11;
  undefined1 auStack_88 [32];
  undefined4 local_68;
  undefined8 ***local_60 [2];
  ulonglong local_50;
  ulonglong local_48;
  ulonglong local_40;
  
  local_40 = DAT_1403eef38 ^ (ulonglong)auStack_88;
  local_68 = 0;
  plVar8 = (longlong *)(param_1 + 0x80);
  lVar2 = *(longlong *)(param_1 + 0x90);
  uVar11 = param_3[2];
  if (0x7ffffffffffffffeU - lVar2 < uVar11) {
                    /* WARNING: Subroutine does not return */
    FUN_140027fd0();
  }
  if (7 < *(ulonglong *)(param_1 + 0x98)) {
    plVar8 = (longlong *)*plVar8;
  }
  if (7 < (ulonglong)param_3[3]) {
    param_3 = (undefined8 *)*param_3;
  }
  local_60[0] = (undefined8 ****)0x0;
  local_50 = 0;
  local_48 = 0;
  uVar1 = lVar2 + uVar11;
  uVar7 = 7;
  ppppuVar9 = local_60;
  ppppuVar4 = (undefined8 ****)local_60[0];
  if (7 < uVar1) {
    uVar7 = uVar1 | 7;
    if (uVar7 < 0x7fffffffffffffff) {
      if (uVar7 < 10) {
        uVar7 = 10;
      }
      if (0x7fffffffffffffff < uVar7 + 1) goto LAB_14029f69c;
      uVar6 = (uVar7 + 1) * 2;
      if (uVar6 < 0x1000) {
        ppppuVar9 = (undefined8 ****)0x0;
        ppppuVar4 = (undefined8 ****)0x0;
        if (uVar6 != 0) {
          ppppuVar9 = operator_new(uVar6);
          ppppuVar4 = ppppuVar9;
        }
        goto LAB_14029f58e;
      }
    }
    else {
      uVar7 = 0x7ffffffffffffffe;
      uVar6 = 0xfffffffffffffffe;
    }
    if (uVar6 + 0x27 <= uVar6) {
LAB_14029f69c:
                    /* WARNING: Subroutine does not return */
      FUN_140027ec0();
    }
    pppuVar5 = operator_new(uVar6 + 0x27);
    if (pppuVar5 == (undefined8 ***)0x0) {
      (*(code *)0x3d7636)();
      pcVar3 = (code *)swi(3);
      (*pcVar3)();
      return;
    }
    ppppuVar9 = (undefined8 ****)((longlong)pppuVar5 + 0x27U & 0xffffffffffffffe0);
    ppppuVar9[-1] = pppuVar5;
    ppppuVar4 = ppppuVar9;
  }
LAB_14029f58e:
  local_60[0] = ppppuVar4;
  local_50 = uVar1;
  local_48 = uVar7;
  FUN_1402b8fa7(ppppuVar9,plVar8,lVar2 * 2);
  FUN_1402b8fa7((void *)(lVar2 * 2 + (longlong)ppppuVar9),param_3,uVar11 * 2);
  uVar7 = 0;
  *(undefined2 *)((longlong)ppppuVar9 + uVar1 * 2) = 0;
  uVar11 = uVar7;
  do {
    ppppuVar9 = local_60;
    if (7 < local_48) {
      ppppuVar9 = (undefined8 ****)local_60[0];
    }
    *(char *)(uVar11 + param_2) =
         (char)uVar7 + *(char *)((longlong)ppppuVar9 + (uVar11 % local_50) * 2);
    uVar10 = (int)uVar7 + 1;
    uVar7 = (ulonglong)uVar10;
    uVar11 = uVar11 + 1;
  } while ((int)uVar10 < 0x80);
  local_68 = 0;
  if (7 < local_48) {
    uVar11 = local_48 * 2 + 2;
    ppppuVar9 = (undefined8 ****)local_60[0];
    if (0xfff < uVar11) {
      uVar11 = local_48 * 2 + 0x29;
      ppppuVar9 = (undefined8 ****)local_60[0][-1];
      if (0x1f < (ulonglong)((longlong)local_60[0] + (-8 - (longlong)ppppuVar9))) {
        (*(code *)0x3d7636)();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
    }
    thunk_FUN_1402b909d(ppppuVar9,uVar11);
  }
  return;
}


