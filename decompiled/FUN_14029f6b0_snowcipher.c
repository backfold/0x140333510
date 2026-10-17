
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

void FUN_14029f6b0(longlong param_1,longlong param_2,undefined8 *param_3)

{
  ulonglong uVar1;
  longlong lVar2;
  code *pcVar3;
  undefined8 ****ppppuVar4;
  undefined8 ***pppuVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  longlong *plVar9;
  undefined8 ****ppppuVar10;
  uint uVar11;
  undefined1 auStack_88 [32];
  undefined4 local_68;
  undefined8 ***local_60 [2];
  ulonglong local_50;
  ulonglong local_48;
  ulonglong local_40;
  
  local_40 = DAT_1403eef38 ^ (ulonglong)auStack_88;
  local_68 = 0;
  plVar9 = (longlong *)(param_1 + 0x80);
  lVar2 = *(longlong *)(param_1 + 0x90);
  uVar7 = param_3[2];
  if (0x7ffffffffffffffeU - lVar2 < uVar7) {
                    /* WARNING: Subroutine does not return */
    FUN_140027fd0();
  }
  if (7 < *(ulonglong *)(param_1 + 0x98)) {
    plVar9 = (longlong *)*plVar9;
  }
  if (7 < (ulonglong)param_3[3]) {
    param_3 = (undefined8 *)*param_3;
  }
  local_60[0] = (undefined8 ****)0x0;
  local_50 = 0;
  local_48 = 0;
  uVar1 = uVar7 + lVar2;
  uVar8 = 7;
  ppppuVar10 = local_60;
  ppppuVar4 = (undefined8 ****)local_60[0];
  if (7 < uVar1) {
    uVar8 = uVar1 | 7;
    if (uVar8 < 0x7fffffffffffffff) {
      if (uVar8 < 10) {
        uVar8 = 10;
      }
      if (0x7fffffffffffffff < uVar8 + 1) goto LAB_14029f906;
      uVar6 = (uVar8 + 1) * 2;
      if (uVar6 < 0x1000) {
        ppppuVar10 = (undefined8 ****)0x0;
        ppppuVar4 = (undefined8 ****)0x0;
        if (uVar6 != 0) {
          ppppuVar10 = operator_new(uVar6);
          ppppuVar4 = ppppuVar10;
        }
        goto LAB_14029f7ce;
      }
    }
    else {
      uVar8 = 0x7ffffffffffffffe;
      uVar6 = 0xfffffffffffffffe;
    }
    if (uVar6 + 0x27 <= uVar6) {
LAB_14029f906:
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
    ppppuVar10 = (undefined8 ****)((longlong)pppuVar5 + 0x27U & 0xffffffffffffffe0);
    ppppuVar10[-1] = pppuVar5;
    ppppuVar4 = ppppuVar10;
  }
LAB_14029f7ce:
  local_60[0] = ppppuVar4;
  local_50 = uVar1;
  local_48 = uVar8;
  FUN_1402b8fa7(ppppuVar10,plVar9,lVar2 * 2);
  FUN_1402b8fa7((void *)(lVar2 * 2 + (longlong)ppppuVar10),param_3,uVar7 * 2);
  uVar8 = 0;
  *(undefined2 *)((longlong)ppppuVar10 + uVar1 * 2) = 0;
  uVar7 = uVar8;
  do {
    ppppuVar10 = local_60;
    if (7 < local_48) {
      ppppuVar10 = (undefined8 ****)local_60[0];
    }
    *(char *)(uVar8 + param_2) =
         *(char *)((longlong)ppppuVar10 + (local_50 - uVar8 % local_50) * 2 + -2) *
         ((char)uVar7 + (char)(uVar7 / 3) * -3 + '\x02') + (char)uVar7;
    uVar11 = (int)uVar7 + 1;
    uVar7 = (ulonglong)uVar11;
    uVar8 = uVar8 + 1;
  } while ((int)uVar11 < 0x80);
  local_68 = 0;
  if (7 < local_48) {
    uVar7 = local_48 * 2 + 2;
    ppppuVar10 = (undefined8 ****)local_60[0];
    if (0xfff < uVar7) {
      uVar7 = local_48 * 2 + 0x29;
      ppppuVar10 = (undefined8 ****)local_60[0][-1];
      if (0x1f < (ulonglong)((longlong)local_60[0] + (-8 - (longlong)ppppuVar10))) {
        (*(code *)0x3d7636)();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
    }
    thunk_FUN_1402b909d(ppppuVar10,uVar7);
  }
  return;
}


