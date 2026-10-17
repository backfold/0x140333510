// REA session 28 — cshell.dll batch_decompile 0x0x181272e40
// status: ok


undefined4 FUN_181272e40(longlong *param_1,undefined1 *param_2,uint param_3,uint *param_4)

{
  undefined1 uVar1;
  undefined2 uVar2;
  uint uVar3;
  DWORD _Seed;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  HANDLE pvVar7;
  undefined1 *lpMem;
  byte bVar8;
  uint uVar9;
  uint uVar10;
  undefined1 *puVar11;
  
  uVar3 = (**(code **)(*param_1 + 0x30))();
  if (uVar3 <= param_3) {
    _Seed = GetTickCount();
    srand(_Seed);
    uVar3 = *param_4;
    pvVar7 = GetProcessHeap();
    lpMem = HeapAlloc(pvVar7,0,(ulonglong)(uVar3 + 10));
    iVar4 = rand();
    if (lpMem == (undefined1 *)0x0) {
      uVar5 = 0xffffffff;
    }
    else {
      iVar6 = rand();
      *lpMem = (char)iVar6;
      uVar1 = (**(code **)(*param_1 + 0x18))(param_1);
      lpMem[1] = uVar1;
      iVar6 = rand();
      lpMem[2] = (char)iVar6;
      *(int *)(lpMem + 3) = iVar4;
      iVar6 = rand();
      uVar9 = 0;
      lpMem[7] = (char)iVar6;
      bVar8 = 0;
      uVar10 = 0;
      uVar3 = 0;
      if (*param_4 != 0) {
        do {
          uVar3 = uVar10 + 8;
          bVar8 = (byte)iVar4 ^ param_2[uVar10] ^ bVar8;
          uVar10 = uVar10 + 1;
          lpMem[uVar3] = bVar8;
          uVar3 = *param_4;
        } while (uVar10 < uVar3);
      }
      uVar10 = uVar3 + 8;
      puVar11 = param_2;
      if (uVar10 != 0) {
        do {
          iVar4 = uVar10 - uVar9;
          uVar9 = uVar9 + 1;
          *puVar11 = lpMem[iVar4 - 1];
          puVar11 = puVar11 + 1;
        } while (uVar9 < uVar10);
      }
      uVar2 = FUN_181272bc0(param_1,param_2,uVar10);
      *(undefined2 *)(param_2 + uVar10) = uVar2;
      *param_4 = uVar3 + 10;
      pvVar7 = GetProcessHeap();
      HeapFree(pvVar7,0,lpMem);
      uVar5 = 0;
    }
    return uVar5;
  }
  return 0xfffffffc;
}


