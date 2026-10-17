// Function: 0x1402644b8
// REA evidence_id: ev_82a976f0dae33ad652d27b6152cb91352ae037e451e5a183ed92faa19aaeae1e
// Source: suddenattack.exe (sha256 1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741)

ulonglong FUN_1402644b8(void)

{
  code *pcVar1;
  bool bVar2;
  char cVar3;
  undefined1 uVar4;
  undefined2 uVar5;
  int iVar6;
  uint uVar7;
  longlong *plVar8;
  undefined8 uVar9;
  ulonglong uVar10;
  ulonglong unaff_RBX;
  
  __security_init_cookie();
  cVar3 = __scrt_initialize_crt(1);
  if (cVar3 == '\0') {
    FUN_140264900(7);
  }
  else {
    bVar2 = false;
    uVar4 = __scrt_acquire_startup_lock();
    unaff_RBX = CONCAT71((int7)(unaff_RBX >> 8),uVar4);
    if (DAT_14045f698 != 1) {
      if (DAT_14045f698 == 0) {
        DAT_14045f698 = 1;
        iVar6 = FUN_1402b92d1(&DAT_1403017c8,&DAT_1403017e8);
        if (iVar6 != 0) {
          return 0xff;
        }
        FUN_1402b92cb(&DAT_1402ff5c0,&DAT_1403017c0);
        DAT_14045f698 = 2;
      }
      else {
        bVar2 = true;
      }
      __scrt_release_startup_lock(uVar4);
      plVar8 = (longlong *)FUN_140264cd8();
      if ((*plVar8 != 0) && (cVar3 = __scrt_is_nonwritable_in_current_image(plVar8), cVar3 != '\0'))
      {
        FUN_1402d9a60(0,2);
      }
      plVar8 = (longlong *)FUN_140264ce0();
      if ((*plVar8 != 0) && (cVar3 = __scrt_is_nonwritable_in_current_image(plVar8), cVar3 != '\0'))
      {
        FUN_1402b92ef(*plVar8);
      }
      uVar5 = __scrt_get_show_window_mode();
      uVar9 = FUN_1402b92c5();
      uVar7 = FUN_14007acf0(&IMAGE_DOS_HEADER_140000000,0,uVar9,uVar5);
      unaff_RBX = (ulonglong)uVar7;
      cVar3 = __scrt_is_managed_app();
      if (cVar3 != '\0') {
        if (!bVar2) {
          FUN_1402b92ad();
        }
        __scrt_uninitialize_crt(1,0);
        return unaff_RBX;
      }
      goto LAB_14026462d;
    }
  }
  FUN_140264900(7);
LAB_14026462d:
  FUN_1402b92d7(unaff_RBX & 0xffffffff);
  FUN_1402b92dd(unaff_RBX & 0xffffffff);
  pcVar1 = (code *)swi(3);
  uVar10 = (*pcVar1)();
  return uVar10;
}


