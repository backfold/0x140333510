// REA session 28 — cshell.dll batch_decompile 0x0x181272fa0
// status: ok


undefined4 FUN_181272fa0(longlong *param_1,longlong param_2,undefined8 param_3,uint *param_4)

{
  char cVar1;
  short sVar2;
  undefined4 uVar3;
  HANDLE pvVar4;
  undefined1 *lpMem;
  byte bVar5;
  byte bVar6;
  uint uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  uint uVar10;
  undefined1 *puVar11;
  
  uVar10 = *param_4 - 2;
  sVar2 = FUN_181272bc0(param_1,param_2,uVar10);
  if (*(short *)((ulonglong)uVar10 + param_2) == sVar2) {
    pvVar4 = GetProcessHeap();
    lpMem = HeapAlloc(pvVar4,0,(ulonglong)uVar10);
    if (lpMem == (undefined1 *)0x0) {
      uVar3 = 0xffffffff;
    }
    else {
      uVar9 = 0;
      uVar8 = uVar9;
      puVar11 = lpMem;
      if (uVar10 != 0) {
        do {
          uVar7 = (int)uVar8 + 1;
          *puVar11 = *(undefined1 *)((ulonglong)((uVar10 - (int)uVar8) - 1) + param_2);
          uVar8 = (ulonglong)uVar7;
          puVar11 = puVar11 + 1;
        } while (uVar7 < uVar10);
      }
      cVar1 = (**(code **)(*param_1 + 0x18))();
      if (lpMem[1] == cVar1) {
        uVar3 = *(undefined4 *)(lpMem + 3);
        bVar5 = 0;
        *param_4 = *param_4 - 10;
        if (*param_4 != 0) {
          do {
            bVar6 = (byte)uVar3 ^ bVar5;
            bVar5 = lpMem[(int)uVar9 + 8];
            *(byte *)(uVar9 + param_2) = bVar6 ^ bVar5;
            uVar10 = (int)uVar9 + 1;
            uVar9 = (ulonglong)uVar10;
          } while (uVar10 < *param_4);
        }
        pvVar4 = GetProcessHeap();
        HeapFree(pvVar4,0,lpMem);
        uVar3 = 0;
      }
      else {
        pvVar4 = GetProcessHeap();
        HeapFree(pvVar4,0,lpMem);
        uVar3 = 0xfffffffd;
      }
    }
  }
  else {
    uVar3 = 0xfffffffe;
  }
  return uVar3;
}


