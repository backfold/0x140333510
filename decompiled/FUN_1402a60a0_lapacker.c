
int FUN_1402a60a0(longlong param_1)

{
  int iVar1;
  undefined4 uVar2;
  wchar_t *local_res8;
  
  if (*(uint *)(param_1 + 0xa0) <= *(uint *)(param_1 + 0x3c)) {
    return 0;
  }
  iVar1 = FUN_1402a5cb0();
  FUN_1402b8fb3(*(undefined8 *)(param_1 + 0x98),0,iVar1);
  *(undefined8 *)(param_1 + 0x30) = *(undefined8 *)(param_1 + 0x98);
  *(int *)(param_1 + 0x38) = iVar1;
  if (*(int *)(param_1 + 0x28) == 0) {
    uVar2 = FUN_1402a5e70(param_1);
    uVar2 = (**(code **)(**(longlong **)(param_1 + 8) + 0x48))
                      (*(longlong **)(param_1 + 8),*(undefined8 *)(param_1 + 0x80),uVar2);
    iVar1 = *(int *)(param_1 + 0x38);
    *(undefined4 *)(param_1 + 0x28) = uVar2;
    *(undefined8 *)(param_1 + 0x20) = *(undefined8 *)(param_1 + 0x80);
  }
  do {
    if (iVar1 == 0) {
LAB_1402a6165:
      return *(int *)(param_1 + 0x30) - *(int *)(param_1 + 0x98);
    }
    iVar1 = FUN_14026cbd0(param_1 + 0x20,0);
    if (iVar1 != 0) {
      if (iVar1 == 1) {
        *(undefined1 *)(param_1 + 0x78) = 1;
        if (*(longlong *)(param_1 + 0x80) != 0) {
          (*(code *)0x3d7768)();
          *(undefined8 *)(param_1 + 0x80) = 0;
          *(undefined4 *)(param_1 + 0x88) = 0;
        }
      }
      else if (iVar1 != -5) {
        local_res8 = L"zlib inflate() error. invalid package file data.";
                    /* WARNING: Subroutine does not return */
        FUN_1402b8f9b(&local_res8,&DAT_1403d37b0);
      }
      goto LAB_1402a6165;
    }
    if (*(int *)(param_1 + 0x28) == 0) {
      uVar2 = FUN_1402a5e70(param_1);
      uVar2 = (**(code **)(**(longlong **)(param_1 + 8) + 0x48))
                        (*(longlong **)(param_1 + 8),*(undefined8 *)(param_1 + 0x80),uVar2);
      *(undefined4 *)(param_1 + 0x28) = uVar2;
      *(undefined8 *)(param_1 + 0x20) = *(undefined8 *)(param_1 + 0x80);
    }
    iVar1 = *(int *)(param_1 + 0x38);
  } while( true );
}


