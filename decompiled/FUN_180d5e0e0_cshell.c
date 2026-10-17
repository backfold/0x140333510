// REA session 28 — cshell.dll batch_decompile 0x0x180d5e0e0
// status: ok


/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 * FUN_180d5e0e0(undefined8 *param_1,undefined8 param_2)

{
  undefined8 ***pppuVar1;
  longlong lVar2;
  undefined8 ****ppppuVar3;
  ulonglong _Size;
  longlong lVar5;
  void *_Dst;
  undefined1 auStack_98 [32];
  ulonglong local_78;
  char local_68 [8];
  undefined8 local_60;
  undefined8 ***local_58 [2];
  longlong local_48;
  ulonglong uStack_40;
  undefined8 *local_38;
  ulonglong local_30;
  ulonglong uVar4;
  
  local_30 = DAT_1818e6cd8 ^ (ulonglong)auStack_98;
  lVar5 = 0;
  local_68[4] = '\0';
  local_68[5] = '\0';
  local_68[6] = '\0';
  local_68[7] = '\0';
  local_60 = param_2;
  local_38 = param_1;
  FUN_180d5ef00(&local_60,&local_38);
  local_48 = 0;
  uStack_40 = 0xf;
  local_58[0] = (undefined8 ***)0x0;
  local_68[4] = '\x02';
  local_68[5] = '\0';
  local_68[6] = '\0';
  local_68[7] = '\0';
  ppppuVar3 = (undefined8 ****)FUN_181371f54(0x20);
  uStack_40 = 0x1f;
  *(undefined1 *)ppppuVar3 = local_58[0]._0_1_;
  local_58[0] = ppppuVar3;
  local_48 = 0;
  do {
    FUN_18006b8b0(local_68,&DAT_1815ffd30,*(undefined1 *)((longlong)&local_38 + lVar5));
    uVar4 = 0xffffffffffffffff;
    do {
      _Size = uVar4 + 1;
      lVar2 = uVar4 + 1;
      uVar4 = _Size;
    } while (local_68[lVar2] != '\0');
    if (uStack_40 - local_48 < _Size) {
      local_78 = _Size;
      FUN_180095bb0(local_58,_Size,0,local_68);
    }
    else {
      ppppuVar3 = local_58;
      if (0xf < uStack_40) {
        ppppuVar3 = (undefined8 ****)local_58[0];
      }
      _Dst = (void *)((longlong)ppppuVar3 + local_48);
      local_48 = _Size + local_48;
      memmove(_Dst,local_68,_Size);
      *(undefined1 *)(_Size + (longlong)_Dst) = 0;
    }
    lVar2 = local_48;
    lVar5 = lVar5 + 1;
  } while (lVar5 < 8);
  if (uStack_40 - local_48 < 2) {
    local_78 = 2;
    ppppuVar3 = (undefined8 ****)FUN_180095bb0(local_58,2,0,&DAT_1815ffd38);
  }
  else {
    local_48 = local_48 + 2;
    ppppuVar3 = local_58;
    if (0xf < uStack_40) {
      ppppuVar3 = (undefined8 ****)local_58[0];
    }
    *(undefined2 *)((longlong)ppppuVar3 + lVar2) = 0x4153;
    *(undefined1 *)((longlong)ppppuVar3 + lVar2 + 2) = 0;
    ppppuVar3 = local_58;
  }
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  pppuVar1 = ppppuVar3[1];
  *param_1 = *ppppuVar3;
  param_1[1] = pppuVar1;
  pppuVar1 = ppppuVar3[3];
  param_1[2] = ppppuVar3[2];
  param_1[3] = pppuVar1;
  ppppuVar3[2] = (undefined8 ***)0x0;
  ppppuVar3[3] = (undefined8 ***)0xf;
  *(undefined1 *)ppppuVar3 = 0;
  if (0xf < uStack_40) {
    ppppuVar3 = (undefined8 ****)local_58[0];
    if ((0xfff < uStack_40 + 1) &&
       (ppppuVar3 = (undefined8 ****)local_58[0][-1],
       0x1f < (ulonglong)((longlong)local_58[0] + (-8 - (longlong)ppppuVar3)))) {
                    /* WARNING: Subroutine does not return */
      _invalid_parameter_noinfo_noreturn();
    }
    free(ppppuVar3);
  }
  return param_1;
}


