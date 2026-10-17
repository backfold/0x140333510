
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int FUN_14029f920(longlong param_1)

{
  ulonglong *puVar1;
  ulonglong *puVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  undefined1 auVar5 [16];
  undefined1 auVar6 [16];
  undefined1 in_XMM1 [16];
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined1 auVar11 [16];
  
  uVar4 = 0;
  puVar1 = (ulonglong *)(param_1 + 0x80);
  if (*(ulonglong *)(param_1 + 0x98) < 8) {
    puVar2 = (ulonglong *)((longlong)puVar1 + *(longlong *)(param_1 + 0x90) * 2);
  }
  else {
    uVar3 = *puVar1;
    puVar1 = (ulonglong *)*puVar1;
    puVar2 = (ulonglong *)(uVar3 + *(longlong *)(param_1 + 0x90) * 2);
  }
  uVar3 = (ulonglong)((longlong)puVar2 + (1 - (longlong)puVar1)) >> 1;
  if (puVar2 < puVar1) {
    uVar3 = uVar4;
  }
  if (((uVar3 != 0) && (7 < uVar3)) && (1 < DAT_1403eef50)) {
    iVar7 = 0;
    iVar8 = 0;
    iVar9 = 0;
    iVar10 = 0;
    auVar11 = ZEXT816(0);
    do {
      auVar5._8_8_ = 0;
      auVar5._0_8_ = *puVar1;
      uVar4 = uVar4 + 8;
      auVar5 = pmovzxwd(in_XMM1,auVar5);
      auVar6._8_8_ = 0;
      auVar6._0_8_ = puVar1[1];
      puVar1 = puVar1 + 2;
      auVar5 = pmulld(auVar5,_DAT_140333440);
      iVar7 = iVar7 + auVar5._0_4_;
      iVar8 = iVar8 + auVar5._4_4_;
      iVar9 = iVar9 + auVar5._8_4_;
      iVar10 = iVar10 + auVar5._12_4_;
      auVar5 = pmovzxwd(auVar5,auVar6);
      auVar5 = pmulld(auVar5,_DAT_140333440);
      in_XMM1._0_4_ = auVar5._0_4_ + auVar11._0_4_;
      in_XMM1._4_4_ = auVar5._4_4_ + auVar11._4_4_;
      in_XMM1._8_4_ = auVar5._8_4_ + auVar11._8_4_;
      in_XMM1._12_4_ = auVar5._12_4_ + auVar11._12_4_;
      auVar11 = in_XMM1;
    } while (uVar4 != (uVar3 & 0xfffffffffffffff8));
    uVar4 = (ulonglong)
            (uint)(iVar7 + in_XMM1._0_4_ + iVar9 + in_XMM1._8_4_ +
                  iVar8 + in_XMM1._4_4_ + iVar10 + in_XMM1._12_4_);
  }
  for (; iVar7 = (int)uVar4, puVar1 != puVar2; puVar1 = (ulonglong *)((longlong)puVar1 + 2)) {
    uVar4 = (ulonglong)(iVar7 + (uint)(ushort)*puVar1 * 3);
  }
  iVar8 = (int)(uVar4 * 0x3521cfb3 >> 0x20);
  return iVar7 + (((uint)(iVar7 - iVar8) >> 1) + iVar8 >> 7) * -0xd4 + 0x21;
}


