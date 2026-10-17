
int FUN_1402b15b0(longlong param_1)

{
  uint uVar1;
  uint *puVar2;
  undefined1 auVar3 [13];
  undefined1 auVar4 [13];
  undefined1 auVar5 [13];
  undefined1 auVar6 [13];
  undefined1 auVar7 [13];
  undefined1 auVar8 [13];
  undefined1 auVar9 [13];
  undefined1 auVar10 [13];
  uint5 uVar11;
  undefined1 auVar12 [13];
  undefined1 auVar13 [13];
  undefined1 auVar14 [13];
  undefined1 auVar15 [13];
  undefined1 auVar16 [13];
  undefined1 auVar17 [13];
  undefined1 auVar18 [13];
  undefined1 auVar19 [13];
  uint *puVar20;
  uint *puVar21;
  int iVar22;
  uint *puVar23;
  longlong lVar24;
  longlong lVar25;
  int iVar26;
  int iVar27;
  int iVar28;
  int iVar29;
  int iVar30;
  int iVar31;
  int iVar32;
  int iVar33;
  int iVar34;
  int iVar35;
  int iVar36;
  int iVar37;
  int iVar38;
  int iVar39;
  int iVar40;
  int iVar41;
  
  puVar21 = *(uint **)(param_1 + 0x18);
  puVar2 = *(uint **)(param_1 + 0x20);
  iVar22 = (int)((longlong)puVar2 - (longlong)puVar21 >> 4) + *(int *)(param_1 + 0x14) +
           *(int *)(param_1 + 0x10) + *(int *)(param_1 + 0xc) + *(int *)(param_1 + 8) +
           *(int *)(param_1 + 4);
  if (puVar21 != puVar2) {
    iVar34 = 0;
    iVar35 = 0;
    iVar36 = 0;
    iVar37 = 0;
    iVar26 = 0;
    iVar28 = 0;
    iVar30 = 0;
    iVar32 = 0;
    puVar23 = puVar21;
    do {
      puVar23 = puVar23 + 4;
      puVar20 = puVar21;
      lVar25 = 0;
      if (puVar21 <= puVar23) {
        do {
          uVar1 = *puVar20;
          lVar25 = lVar25 + 8;
          auVar3[0xc] = (char)(uVar1 >> 0x18);
          auVar3._0_12_ = ZEXT712(0);
          uVar11 = CONCAT32(auVar3._10_3_,(ushort)(byte)(uVar1 >> 0x10));
          auVar12._5_8_ = 0;
          auVar12._0_5_ = uVar11;
          iVar34 = iVar34 + (uVar1 & 0xff);
          iVar35 = iVar35 + (int)CONCAT72(SUB137(auVar12 << 0x40,6),(ushort)(byte)(uVar1 >> 8));
          iVar36 = iVar36 + (int)uVar11;
          iVar37 = iVar37 + (uint)(uint3)(auVar3._10_3_ >> 0x10);
          uVar1 = puVar20[1];
          puVar20 = puVar20 + 2;
          auVar4[0xc] = (char)(uVar1 >> 0x18);
          auVar4._0_12_ = ZEXT712(0);
          uVar11 = CONCAT32(auVar4._10_3_,(ushort)(byte)(uVar1 >> 0x10));
          auVar13._5_8_ = 0;
          auVar13._0_5_ = uVar11;
          iVar26 = iVar26 + (uVar1 & 0xff);
          iVar28 = iVar28 + (int)CONCAT72(SUB137(auVar13 << 0x40,6),(ushort)(byte)(uVar1 >> 8));
          iVar30 = iVar30 + (int)uVar11;
          iVar32 = iVar32 + (uint)(uint3)(auVar4._10_3_ >> 0x10);
        } while (lVar25 != 0x10);
      }
      for (; puVar20 != puVar23; puVar20 = (uint *)((longlong)puVar20 + 1)) {
        iVar22 = iVar22 + (uint)(byte)*puVar20;
      }
      puVar21 = puVar21 + 4;
    } while (puVar21 != puVar2);
    iVar22 = iVar22 + iVar26 + iVar34 + iVar30 + iVar36 + iVar28 + iVar35 + iVar32 + iVar37;
  }
  lVar25 = 2;
  iVar34 = 0;
  iVar35 = 0;
  iVar36 = 0;
  iVar37 = 0;
  lVar24 = 2;
  iVar38 = 0;
  iVar39 = 0;
  iVar40 = 0;
  iVar41 = 0;
  iVar26 = 0;
  iVar28 = 0;
  iVar30 = 0;
  iVar32 = 0;
  puVar21 = (uint *)(param_1 + 0x30);
  do {
    uVar1 = *puVar21;
    auVar5[0xc] = (char)(uVar1 >> 0x18);
    auVar5._0_12_ = ZEXT712(0);
    uVar11 = CONCAT32(auVar5._10_3_,(ushort)(byte)(uVar1 >> 0x10));
    auVar14._5_8_ = 0;
    auVar14._0_5_ = uVar11;
    iVar38 = iVar38 + (uVar1 & 0xff);
    iVar39 = iVar39 + (int)CONCAT72(SUB137(auVar14 << 0x40,6),(ushort)(byte)(uVar1 >> 8));
    iVar40 = iVar40 + (int)uVar11;
    iVar41 = iVar41 + (uint)(uint3)(auVar5._10_3_ >> 0x10);
    uVar1 = puVar21[1];
    auVar6[0xc] = (char)(uVar1 >> 0x18);
    auVar6._0_12_ = ZEXT712(0);
    uVar11 = CONCAT32(auVar6._10_3_,(ushort)(byte)(uVar1 >> 0x10));
    auVar15._5_8_ = 0;
    auVar15._0_5_ = uVar11;
    iVar26 = iVar26 + (uVar1 & 0xff);
    iVar28 = iVar28 + (int)CONCAT72(SUB137(auVar15 << 0x40,6),(ushort)(byte)(uVar1 >> 8));
    iVar30 = iVar30 + (int)uVar11;
    iVar32 = iVar32 + (uint)(uint3)(auVar6._10_3_ >> 0x10);
    lVar24 = lVar24 + -1;
    puVar21 = puVar21 + 2;
  } while (lVar24 != 0);
  iVar22 = iVar22 + iVar26 + iVar38 + iVar30 + iVar40 + iVar28 + iVar39 + iVar32 + iVar41;
  if ((*(byte *)(param_1 + 4) & 0x10) != 0) {
    iVar38 = 0;
    iVar39 = 0;
    iVar40 = 0;
    iVar41 = 0;
    iVar26 = 0;
    iVar28 = 0;
    iVar30 = 0;
    iVar32 = 0;
    lVar24 = 2;
    puVar21 = (uint *)(param_1 + 0x40);
    do {
      uVar1 = *puVar21;
      auVar7[0xc] = (char)(uVar1 >> 0x18);
      auVar7._0_12_ = ZEXT712(0);
      uVar11 = CONCAT32(auVar7._10_3_,(ushort)(byte)(uVar1 >> 0x10));
      auVar16._5_8_ = 0;
      auVar16._0_5_ = uVar11;
      iVar38 = iVar38 + (uVar1 & 0xff);
      iVar39 = iVar39 + (int)CONCAT72(SUB137(auVar16 << 0x40,6),(ushort)(byte)(uVar1 >> 8));
      iVar40 = iVar40 + (int)uVar11;
      iVar41 = iVar41 + (uint)(uint3)(auVar7._10_3_ >> 0x10);
      uVar1 = puVar21[1];
      auVar8[0xc] = (char)(uVar1 >> 0x18);
      auVar8._0_12_ = ZEXT712(0);
      uVar11 = CONCAT32(auVar8._10_3_,(ushort)(byte)(uVar1 >> 0x10));
      auVar17._5_8_ = 0;
      auVar17._0_5_ = uVar11;
      iVar26 = iVar26 + (uVar1 & 0xff);
      iVar28 = iVar28 + (int)CONCAT72(SUB137(auVar17 << 0x40,6),(ushort)(byte)(uVar1 >> 8));
      iVar30 = iVar30 + (int)uVar11;
      iVar32 = iVar32 + (uint)(uint3)(auVar8._10_3_ >> 0x10);
      lVar24 = lVar24 + -1;
      puVar21 = puVar21 + 2;
    } while (lVar24 != 0);
    iVar27 = 0;
    iVar29 = 0;
    iVar31 = 0;
    iVar33 = 0;
    puVar21 = (uint *)(param_1 + 0x50);
    do {
      uVar1 = *puVar21;
      auVar9[0xc] = (char)(uVar1 >> 0x18);
      auVar9._0_12_ = ZEXT712(0);
      uVar11 = CONCAT32(auVar9._10_3_,(ushort)(byte)(uVar1 >> 0x10));
      auVar18._5_8_ = 0;
      auVar18._0_5_ = uVar11;
      iVar34 = iVar34 + (uVar1 & 0xff);
      iVar35 = iVar35 + (int)CONCAT72(SUB137(auVar18 << 0x40,6),(ushort)(byte)(uVar1 >> 8));
      iVar36 = iVar36 + (int)uVar11;
      iVar37 = iVar37 + (uint)(uint3)(auVar9._10_3_ >> 0x10);
      uVar1 = puVar21[1];
      auVar10[0xc] = (char)(uVar1 >> 0x18);
      auVar10._0_12_ = ZEXT712(0);
      uVar11 = CONCAT32(auVar10._10_3_,(ushort)(byte)(uVar1 >> 0x10));
      auVar19._5_8_ = 0;
      auVar19._0_5_ = uVar11;
      iVar27 = iVar27 + (uVar1 & 0xff);
      iVar29 = iVar29 + (int)CONCAT72(SUB137(auVar19 << 0x40,6),(ushort)(byte)(uVar1 >> 8));
      iVar31 = iVar31 + (int)uVar11;
      iVar33 = iVar33 + (uint)(uint3)(auVar10._10_3_ >> 0x10);
      lVar25 = lVar25 + -1;
      puVar21 = puVar21 + 2;
    } while (lVar25 != 0);
    return iVar27 + iVar34 + iVar31 + iVar36 + iVar29 + iVar35 + iVar33 + iVar37 +
           iVar22 + iVar26 + iVar38 + iVar30 + iVar40 + iVar28 + iVar39 + iVar32 + iVar41;
  }
  return iVar22;
}

