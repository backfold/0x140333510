
int FUN_1402a6340(longlong param_1,char param_2)

{
  undefined4 uVar1;
  int iVar2;
  longlong lVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  wchar_t *local_res8;
  undefined1 local_58 [24];
  undefined1 local_40 [24];
  
  uVar6 = *(uint *)(param_1 + 0xa8);
  uVar7 = uVar6 / DAT_1403ef150;
  iVar4 = 0;
  if ((*(uint *)(param_1 + 0xa4) == uVar6) && (uVar6 != 0)) goto LAB_1402a6439;
  if ((uVar6 < *(uint *)(param_1 + 0xa4)) && (uVar6 < *(int *)(param_1 + 0x3c) - DAT_1403ef150)) {
    if (*(int *)(param_1 + 0x18) == 1) {
      *(undefined4 *)(param_1 + 0x18) = 0;
      inflateEnd(param_1 + 0x20);
      if (*(longlong *)(param_1 + 0x80) != 0) {
        (*(code *)0x3d7768)();
        *(undefined8 *)(param_1 + 0x80) = 0;
        *(undefined4 *)(param_1 + 0x88) = 0;
      }
      goto LAB_1402a63d7;
    }
LAB_1402a63dd:
    *(undefined4 *)(param_1 + 0x18) = 1;
    *(undefined8 *)(param_1 + 0x20) = 0;
    *(undefined8 *)(param_1 + 0x28) = 0;
    *(undefined8 *)(param_1 + 0x30) = 0;
    *(undefined8 *)(param_1 + 0x38) = 0;
    *(undefined8 *)(param_1 + 0x40) = 0;
    *(undefined8 *)(param_1 + 0x48) = 0;
    *(undefined8 *)(param_1 + 0x50) = 0;
    *(undefined8 *)(param_1 + 0x58) = 0;
    *(undefined8 *)(param_1 + 0x60) = 0;
    *(undefined8 *)(param_1 + 0x68) = 0;
    *(undefined8 *)(param_1 + 0x70) = 0;
    inflateInit_((undefined8 *)(param_1 + 0x20),"1.2.11",0x58);
  }
  else {
    if (*(int *)(param_1 + 0x18) != 0) goto LAB_1402a6439;
LAB_1402a63d7:
    if (*(int *)(param_1 + 0x18) != 1) goto LAB_1402a63dd;
  }
  (**(code **)(**(longlong **)(param_1 + 8) + 0x28))
            (*(longlong **)(param_1 + 8),*(undefined4 *)(param_1 + 0xac),0);
  *(undefined1 *)(param_1 + 0x78) = 0;
  FUN_1402a5cb0(param_1);
LAB_1402a6439:
  uVar6 = *(uint *)(param_1 + 0x3c);
  uVar5 = DAT_1403ef150;
  do {
    iVar2 = 0;
    if (uVar6 < *(uint *)(param_1 + 0xa0)) {
      lVar3 = *(longlong *)(param_1 + 0x98);
      if (lVar3 == 0) {
        lVar3 = (*(code *)0x3d7912)((longlong)(int)uVar5);
        *(longlong *)(param_1 + 0x98) = lVar3;
        if (lVar3 == 0) {
          FUN_1402646d0(local_58);
                    /* WARNING: Subroutine does not return */
          FUN_1402b8f9b(local_58,&DAT_1403d3668);
        }
        FUN_1402b8fb3(lVar3,0,(longlong)(int)uVar5);
        lVar3 = *(longlong *)(param_1 + 0x98);
      }
      FUN_1402b8fb3(lVar3,0,uVar5);
      *(undefined8 *)(param_1 + 0x30) = *(undefined8 *)(param_1 + 0x98);
      *(uint *)(param_1 + 0x38) = uVar5;
      if (*(int *)(param_1 + 0x28) == 0) {
        uVar1 = FUN_1402a5e70(param_1);
        uVar1 = (**(code **)(**(longlong **)(param_1 + 8) + 0x48))
                          (*(longlong **)(param_1 + 8),*(undefined8 *)(param_1 + 0x80),uVar1);
        uVar5 = *(uint *)(param_1 + 0x38);
        *(undefined4 *)(param_1 + 0x28) = uVar1;
        *(undefined8 *)(param_1 + 0x20) = *(undefined8 *)(param_1 + 0x80);
      }
      while (uVar5 != 0) {
        iVar2 = FUN_14026cbd0(param_1 + 0x20);
        if (iVar2 != 0) {
          if (iVar2 == 1) {
            *(undefined1 *)(param_1 + 0x78) = 1;
            if (*(longlong *)(param_1 + 0x80) != 0) {
              (*(code *)0x3d7768)();
              *(undefined8 *)(param_1 + 0x80) = 0;
              *(undefined4 *)(param_1 + 0x88) = 0;
            }
          }
          else if (iVar2 != -5) {
            local_res8 = L"zlib inflate() error. invalid package file data.";
                    /* WARNING: Subroutine does not return */
            FUN_1402b8f9b(&local_res8,&DAT_1403d37b0);
          }
          break;
        }
        if (*(int *)(param_1 + 0x28) == 0) {
          iVar2 = (**(code **)(**(longlong **)(param_1 + 8) + 0x20))();
          uVar6 = *(int *)(param_1 + 0xa0) - iVar2;
          lVar3 = *(longlong *)(param_1 + 0x80);
          if (DAT_1403ef150 < uVar6) {
            uVar6 = DAT_1403ef150;
          }
          if (lVar3 == 0) {
LAB_1402a6547:
            lVar3 = (*(code *)0x3d7912)(uVar6);
            *(longlong *)(param_1 + 0x80) = lVar3;
            *(uint *)(param_1 + 0x88) = uVar6;
          }
          else if (*(uint *)(param_1 + 0x88) < uVar6) {
            (*(code *)0x3d7768)(lVar3);
            *(undefined8 *)(param_1 + 0x80) = 0;
            *(undefined4 *)(param_1 + 0x88) = 0;
            goto LAB_1402a6547;
          }
          if (lVar3 == 0) {
            FUN_1402646d0(local_40);
                    /* WARNING: Subroutine does not return */
            FUN_1402b8f9b(local_40,&DAT_1403d3668);
          }
          FUN_1402b8fb3(lVar3,0,uVar6);
          uVar1 = (**(code **)(**(longlong **)(param_1 + 8) + 0x48))
                            (*(longlong **)(param_1 + 8),*(undefined8 *)(param_1 + 0x80),uVar6);
          *(undefined4 *)(param_1 + 0x28) = uVar1;
          *(undefined8 *)(param_1 + 0x20) = *(undefined8 *)(param_1 + 0x80);
        }
        uVar5 = *(uint *)(param_1 + 0x38);
      }
      uVar5 = DAT_1403ef150;
      iVar2 = *(int *)(param_1 + 0x30) - *(int *)(param_1 + 0x98);
    }
    iVar4 = iVar4 + iVar2;
    if (((param_2 == '\0') || (*(char *)(param_1 + 0x78) != '\0')) ||
       (uVar6 = *(uint *)(param_1 + 0x3c), uVar7 <= (uVar6 - 1) / uVar5)) {
      return iVar4;
    }
  } while( true );
}


