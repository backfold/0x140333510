
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

void FUN_180d5e6c0(undefined8 *param_1,undefined1 *param_2,int param_3)

{
  long lVar1;
  ulonglong uVar2;
  undefined8 *puVar3;
  ulonglong uVar4;
  char ****ppppcVar5;
  ulonglong uVar6;
  ulonglong _Size;
  char *****pppppcVar7;
  int iVar8;
  int iVar9;
  undefined1 auStack_88 [32];
  int local_68;
  char ****local_60 [2];
  ulonglong local_50;
  ulonglong local_48;
  ulonglong local_40;
  
  if (0 < param_3) {
    local_40 = DAT_1818e6cd8 ^ (ulonglong)auStack_88;
    iVar9 = 0;
    iVar8 = iVar9;
    local_68 = param_3;
    do {
      pppppcVar7 = (char *****)0x0;
      uVar6 = (ulonglong)iVar9;
      local_60[0] = (char ****)0x0;
      local_50 = 0;
      local_48 = 0xf;
      if ((ulonglong)param_1[2] < uVar6) {
                    /* WARNING: Subroutine does not return */
        FUN_18008ae20();
      }
      uVar2 = param_1[2] - uVar6;
      _Size = 2;
      if (uVar2 < 2) {
        _Size = uVar2;
      }
      puVar3 = param_1;
      if (0xf < (ulonglong)param_1[3]) {
        puVar3 = (undefined8 *)*param_1;
      }
      if (_Size < 0x10) {
        local_50 = _Size;
        memmove(local_60,(void *)((longlong)puVar3 + uVar6),_Size);
        *(undefined1 *)((longlong)local_60 + _Size) = 0;
      }
      else {
        if (0x7fffffffffffffff < _Size) {
                    /* WARNING: Subroutine does not return */
          FUN_180046770();
        }
        uVar2 = _Size | 0xf;
        if (uVar2 < 0x8000000000000000) {
          if (uVar2 < 0x16) {
            uVar2 = 0x16;
          }
          if (0xfff < uVar2 + 1) {
            uVar4 = uVar2 + 0x28;
            if (uVar4 <= uVar2 + 1) {
                    /* WARNING: Subroutine does not return */
              FUN_180046660();
            }
            goto LAB_180d5e7d4;
          }
          if (uVar2 != 0xffffffffffffffff) {
            pppppcVar7 = (char *****)FUN_181371f54();
          }
        }
        else {
          uVar2 = 0x7fffffffffffffff;
          uVar4 = 0x8000000000000027;
LAB_180d5e7d4:
          ppppcVar5 = (char ****)FUN_181371f54(uVar4);
          if (ppppcVar5 == (char ****)0x0) goto LAB_180d5e898;
          pppppcVar7 = (char *****)((longlong)ppppcVar5 + 0x27U & 0xffffffffffffffe0);
          pppppcVar7[-1] = ppppcVar5;
        }
        local_50 = _Size;
        local_48 = uVar2;
        memcpy(pppppcVar7,(void *)((longlong)puVar3 + uVar6),_Size);
        *(char *)((longlong)pppppcVar7 + _Size) = '\0';
        local_60[0] = (char ****)pppppcVar7;
        param_3 = local_68;
      }
      pppppcVar7 = local_60;
      if (0xf < local_48) {
        pppppcVar7 = (char *****)local_60[0];
      }
      lVar1 = strtol((char *)pppppcVar7,(char **)0x0,0x10);
      *param_2 = (char)lVar1;
      if (0xf < local_48) {
        pppppcVar7 = (char *****)local_60[0];
        if ((0xfff < local_48 + 1) &&
           (pppppcVar7 = (char *****)local_60[0][-1],
           (char *)0x1f < (char *)((longlong)local_60[0] + (-8 - (longlong)pppppcVar7)))) {
LAB_180d5e898:
                    /* WARNING: Subroutine does not return */
          _invalid_parameter_noinfo_noreturn();
        }
        free(pppppcVar7);
      }
      iVar8 = iVar8 + 1;
      iVar9 = iVar9 + 2;
      param_2 = param_2 + 1;
    } while (iVar8 < param_3);
  }
  return;
}

