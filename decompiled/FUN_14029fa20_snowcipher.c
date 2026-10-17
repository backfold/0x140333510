
int FUN_14029fa20(longlong param_1)

{
  ulonglong uVar1;
  undefined1 auVar2 [14];
  undefined1 auVar3 [14];
  undefined1 auVar4 [14];
  undefined1 auVar5 [14];
  undefined1 auVar6 [14];
  undefined1 auVar7 [14];
  ulonglong *puVar8;
  ulonglong *puVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  
  uVar11 = 0;
  puVar8 = (ulonglong *)(param_1 + 0x80);
  if (*(ulonglong *)(param_1 + 0x98) < 8) {
    puVar9 = (ulonglong *)((longlong)puVar8 + *(longlong *)(param_1 + 0x90) * 2);
  }
  else {
    uVar10 = *puVar8;
    puVar8 = (ulonglong *)*puVar8;
    puVar9 = (ulonglong *)(uVar10 + *(longlong *)(param_1 + 0x90) * 2);
  }
  uVar10 = (ulonglong)((longlong)puVar9 + (1 - (longlong)puVar8)) >> 1;
  if (puVar9 < puVar8) {
    uVar10 = uVar11;
  }
  if ((uVar10 != 0) && (7 < uVar10)) {
    iVar16 = 0;
    iVar17 = 0;
    iVar18 = 0;
    iVar19 = 0;
    iVar12 = 0;
    iVar13 = 0;
    iVar14 = 0;
    iVar15 = 0;
    do {
      uVar1 = *puVar8;
      auVar2._8_4_ = 0;
      auVar2._0_8_ = uVar1;
      auVar2._12_2_ = (short)(uVar1 >> 0x30);
      auVar4._8_2_ = (short)(uVar1 >> 0x20);
      auVar4._0_8_ = uVar1;
      auVar4._10_4_ = auVar2._10_4_;
      auVar6._6_8_ = 0;
      auVar6._0_6_ = auVar4._8_6_;
      uVar11 = uVar11 + 8;
      iVar16 = iVar16 + (uint)(ushort)uVar1;
      iVar17 = iVar17 + (int)CONCAT82(SUB148(auVar6 << 0x40,6),(short)(uVar1 >> 0x10));
      iVar18 = iVar18 + auVar4._8_4_;
      iVar19 = iVar19 + (auVar2._10_4_ >> 0x10);
      uVar1 = puVar8[1];
      auVar3._8_4_ = 0;
      auVar3._0_8_ = uVar1;
      auVar3._12_2_ = (short)(uVar1 >> 0x30);
      auVar5._8_2_ = (short)(uVar1 >> 0x20);
      auVar5._0_8_ = uVar1;
      auVar5._10_4_ = auVar3._10_4_;
      auVar7._6_8_ = 0;
      auVar7._0_6_ = auVar5._8_6_;
      puVar8 = puVar8 + 2;
      iVar12 = (uint)(ushort)uVar1 + iVar12;
      iVar13 = (int)CONCAT82(SUB148(auVar7 << 0x40,6),(short)(uVar1 >> 0x10)) + iVar13;
      iVar14 = auVar5._8_4_ + iVar14;
      iVar15 = (auVar3._10_4_ >> 0x10) + iVar15;
    } while (uVar11 != (uVar10 & 0xfffffffffffffff8));
    uVar11 = (ulonglong)
             (uint)(iVar16 + iVar12 + iVar18 + iVar14 + iVar17 + iVar13 + iVar19 + iVar15);
  }
  for (; iVar12 = (int)uVar11, puVar8 != puVar9; puVar8 = (ulonglong *)((longlong)puVar8 + 2)) {
    uVar11 = (ulonglong)(iVar12 + (uint)(ushort)*puVar8);
  }
  iVar13 = (int)(uVar11 * 0xa41a41a5 >> 0x20);
  return iVar12 + (((uint)(iVar12 - iVar13) >> 1) + iVar13 >> 8) * -0x138 + 0x1e;
}


