
int FUN_1402b17f0(longlong param_1)

{
  ulonglong *puVar1;
  ulonglong uVar2;
  undefined1 auVar3 [14];
  undefined1 auVar4 [14];
  undefined1 auVar5 [14];
  undefined1 auVar6 [14];
  undefined1 auVar7 [14];
  undefined1 auVar8 [14];
  ulonglong *puVar9;
  ulonglong uVar10;
  int iVar11;
  ulonglong uVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  int iVar20;
  
  puVar9 = (ulonglong *)(param_1 + 0x10);
  iVar11 = *(int *)(param_1 + 0xc);
  if (7 < *(ulonglong *)(param_1 + 0x28)) {
    puVar9 = *(ulonglong **)(param_1 + 0x10);
  }
  uVar12 = 0;
  puVar1 = (ulonglong *)((longlong)puVar9 + *(longlong *)(param_1 + 0x20) * 2);
  uVar10 = (ulonglong)((longlong)puVar1 + (1 - (longlong)puVar9)) >> 1;
  if (puVar1 < puVar9) {
    uVar10 = uVar12;
  }
  if ((uVar10 != 0) && (7 < uVar10)) {
    iVar17 = 0;
    iVar18 = 0;
    iVar19 = 0;
    iVar20 = 0;
    iVar13 = 0;
    iVar14 = 0;
    iVar15 = 0;
    iVar16 = 0;
    do {
      uVar2 = *puVar9;
      auVar3._8_4_ = 0;
      auVar3._0_8_ = uVar2;
      auVar3._12_2_ = (short)(uVar2 >> 0x30);
      auVar5._8_2_ = (short)(uVar2 >> 0x20);
      auVar5._0_8_ = uVar2;
      auVar5._10_4_ = auVar3._10_4_;
      auVar7._6_8_ = 0;
      auVar7._0_6_ = auVar5._8_6_;
      uVar12 = uVar12 + 8;
      iVar17 = iVar17 + (uint)(ushort)uVar2;
      iVar18 = iVar18 + (int)CONCAT82(SUB148(auVar7 << 0x40,6),(short)(uVar2 >> 0x10));
      iVar19 = iVar19 + auVar5._8_4_;
      iVar20 = iVar20 + (auVar3._10_4_ >> 0x10);
      uVar2 = puVar9[1];
      puVar9 = puVar9 + 2;
      auVar4._8_4_ = 0;
      auVar4._0_8_ = uVar2;
      auVar4._12_2_ = (short)(uVar2 >> 0x30);
      auVar6._8_2_ = (short)(uVar2 >> 0x20);
      auVar6._0_8_ = uVar2;
      auVar6._10_4_ = auVar4._10_4_;
      auVar8._6_8_ = 0;
      auVar8._0_6_ = auVar6._8_6_;
      iVar13 = iVar13 + (uint)(ushort)uVar2;
      iVar14 = iVar14 + (int)CONCAT82(SUB148(auVar8 << 0x40,6),(short)(uVar2 >> 0x10));
      iVar15 = iVar15 + auVar6._8_4_;
      iVar16 = iVar16 + (auVar4._10_4_ >> 0x10);
    } while (uVar12 != (uVar10 & 0xfffffffffffffff8));
    iVar11 = iVar11 + iVar13 + iVar17 + iVar15 + iVar19 + iVar14 + iVar18 + iVar16 + iVar20;
  }
  for (; puVar9 != puVar1; puVar9 = (ulonglong *)((longlong)puVar9 + 2)) {
    iVar11 = iVar11 + (uint)(ushort)*puVar9;
  }
  return (uint)*(byte *)(param_1 + 8) + *(int *)(param_1 + 0x34) + iVar11;
}


