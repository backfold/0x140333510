
ushort FUN_181272bc0(undefined8 param_1,longlong param_2,uint param_3)

{
  byte *pbVar1;
  undefined1 auVar2 [16];
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  byte bVar9;
  ushort uVar10;
  char cVar11;
  char cVar13;
  char cVar14;
  undefined4 uVar12;
  char cVar15;
  char cVar16;
  char cVar18;
  char cVar19;
  undefined4 uVar17;
  char cVar20;
  char cVar21;
  char cVar23;
  char cVar24;
  undefined4 uVar22;
  char cVar25;
  char cVar26;
  char cVar28;
  char cVar29;
  undefined4 uVar27;
  char cVar30;
  undefined1 auVar31 [16];
  undefined1 in_XMM4_Ba;
  char cVar32;
  byte bVar33;
  undefined1 in_XMM4_Bb;
  char cVar34;
  undefined1 in_XMM4_Bc;
  char cVar35;
  undefined1 in_XMM4_Bd;
  char cVar36;
  undefined1 in_XMM4_Be;
  char cVar37;
  undefined1 in_XMM4_Bf;
  char cVar38;
  undefined1 in_XMM4_Bg;
  char cVar39;
  undefined1 in_XMM4_Bh;
  char cVar40;
  undefined1 in_XMM4_Bi;
  char cVar41;
  undefined1 in_XMM4_Bj;
  char cVar42;
  undefined1 in_XMM4_Bk;
  char cVar43;
  undefined1 in_XMM4_Bl;
  char cVar44;
  undefined1 in_XMM4_Bm;
  char cVar45;
  undefined1 in_XMM4_Bn;
  char cVar46;
  undefined1 in_XMM4_Bo;
  char cVar47;
  undefined1 in_XMM4_Bp;
  char cVar48;
  undefined1 auVar49 [16];
  
  bVar33 = 0;
  uVar4 = 0;
  uVar7 = 0;
  if (0x1f < param_3) {
    uVar12 = 0;
    uVar17 = 0;
    uVar22 = 0;
    uVar27 = 0;
    uVar4 = CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba))) ^
            CONCAT13(in_XMM4_Bd,CONCAT12(in_XMM4_Bc,CONCAT11(in_XMM4_Bb,in_XMM4_Ba)));
    cVar32 = (char)uVar4;
    cVar34 = (char)(uVar4 >> 8);
    cVar35 = (char)(uVar4 >> 0x10);
    cVar36 = (char)(uVar4 >> 0x18);
    uVar4 = CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be))) ^
            CONCAT13(in_XMM4_Bh,CONCAT12(in_XMM4_Bg,CONCAT11(in_XMM4_Bf,in_XMM4_Be)));
    cVar37 = (char)uVar4;
    cVar38 = (char)(uVar4 >> 8);
    cVar39 = (char)(uVar4 >> 0x10);
    cVar40 = (char)(uVar4 >> 0x18);
    uVar4 = CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi))) ^
            CONCAT13(in_XMM4_Bl,CONCAT12(in_XMM4_Bk,CONCAT11(in_XMM4_Bj,in_XMM4_Bi)));
    cVar41 = (char)uVar4;
    cVar42 = (char)(uVar4 >> 8);
    cVar43 = (char)(uVar4 >> 0x10);
    cVar44 = (char)(uVar4 >> 0x18);
    uVar4 = CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm))) ^
            CONCAT13(in_XMM4_Bp,CONCAT12(in_XMM4_Bo,CONCAT11(in_XMM4_Bn,in_XMM4_Bm)));
    cVar45 = (char)uVar4;
    cVar46 = (char)(uVar4 >> 8);
    cVar47 = (char)(uVar4 >> 0x10);
    cVar48 = (char)(uVar4 >> 0x18);
    auVar31 = ZEXT816(0);
    auVar49 = ZEXT816(0);
    do {
      auVar2 = *(undefined1 (*) [16])(uVar7 + param_2);
      iVar3 = (int)uVar7;
      uVar4 = iVar3 + 0x20;
      uVar7 = (ulonglong)uVar4;
      cVar11 = (char)uVar12 + auVar2[0];
      cVar13 = (char)((uint)uVar12 >> 8) + auVar2[1];
      cVar14 = (char)((uint)uVar12 >> 0x10) + auVar2[2];
      cVar15 = (char)((uint)uVar12 >> 0x18) + auVar2[3];
      uVar12 = CONCAT13(cVar15,CONCAT12(cVar14,CONCAT11(cVar13,cVar11)));
      cVar16 = (char)uVar17 + auVar2[4];
      cVar18 = (char)((uint)uVar17 >> 8) + auVar2[5];
      cVar19 = (char)((uint)uVar17 >> 0x10) + auVar2[6];
      cVar20 = (char)((uint)uVar17 >> 0x18) + auVar2[7];
      uVar17 = CONCAT13(cVar20,CONCAT12(cVar19,CONCAT11(cVar18,cVar16)));
      cVar21 = (char)uVar22 + auVar2[8];
      cVar23 = (char)((uint)uVar22 >> 8) + auVar2[9];
      cVar24 = (char)((uint)uVar22 >> 0x10) + auVar2[10];
      cVar25 = (char)((uint)uVar22 >> 0x18) + auVar2[0xb];
      uVar22 = CONCAT13(cVar25,CONCAT12(cVar24,CONCAT11(cVar23,cVar21)));
      cVar26 = (char)uVar27 + auVar2[0xc];
      cVar28 = (char)((uint)uVar27 >> 8) + auVar2[0xd];
      cVar29 = (char)((uint)uVar27 >> 0x10) + auVar2[0xe];
      cVar30 = (char)((uint)uVar27 >> 0x18) + auVar2[0xf];
      uVar27 = CONCAT13(cVar30,CONCAT12(cVar29,CONCAT11(cVar28,cVar26)));
      auVar49 = auVar49 ^ auVar2;
      auVar2 = *(undefined1 (*) [16])((ulonglong)(iVar3 + 0x10) + param_2);
      cVar32 = cVar32 + auVar2[0];
      cVar34 = cVar34 + auVar2[1];
      cVar35 = cVar35 + auVar2[2];
      cVar36 = cVar36 + auVar2[3];
      cVar37 = cVar37 + auVar2[4];
      cVar38 = cVar38 + auVar2[5];
      cVar39 = cVar39 + auVar2[6];
      cVar40 = cVar40 + auVar2[7];
      cVar41 = cVar41 + auVar2[8];
      cVar42 = cVar42 + auVar2[9];
      cVar43 = cVar43 + auVar2[10];
      cVar44 = cVar44 + auVar2[0xb];
      cVar45 = cVar45 + auVar2[0xc];
      cVar46 = cVar46 + auVar2[0xd];
      cVar47 = cVar47 + auVar2[0xe];
      cVar48 = cVar48 + auVar2[0xf];
      auVar31 = auVar31 ^ auVar2;
    } while (uVar4 < (param_3 & 0xffffffe0));
    auVar31 = auVar31 ^ auVar49 ^ (auVar31 ^ auVar49) >> 0x40;
    auVar31 = auVar31 ^ auVar31 >> 0x20;
    auVar31 = auVar31 ^ auVar31 >> 0x10;
    uVar4 = auVar31._0_4_ ^ auVar31._1_4_;
    bVar33 = cVar32 + cVar11 + cVar41 + cVar21 + cVar37 + cVar16 + cVar45 + cVar26 +
             cVar35 + cVar14 + cVar43 + cVar24 + cVar39 + cVar19 + cVar47 + cVar29 +
             cVar34 + cVar13 + cVar42 + cVar23 + cVar38 + cVar18 + cVar46 + cVar28 +
             cVar36 + cVar15 + cVar44 + cVar25 + cVar40 + cVar20 + cVar48 + cVar30;
  }
  uVar10 = (ushort)uVar4;
  bVar9 = (byte)uVar4;
  cVar34 = '\0';
  cVar32 = '\0';
  uVar5 = (uint)uVar7;
  if (param_3 <= uVar5) goto LAB_181272cfa;
  if (param_3 - uVar5 < 2) {
LAB_181272cec:
    bVar33 = bVar33 + *(char *)(uVar7 + param_2);
    bVar9 = bVar9 ^ *(byte *)(uVar7 + param_2);
  }
  else {
    uVar6 = ((param_3 - uVar5) - 2 >> 1) + 1;
    uVar8 = (ulonglong)uVar6;
    do {
      bVar9 = *(byte *)(uVar7 + 1 + param_2);
      cVar34 = cVar34 + *(char *)(uVar7 + param_2);
      cVar32 = cVar32 + bVar9;
      pbVar1 = (byte *)(uVar7 + param_2);
      uVar7 = uVar7 + 2;
      bVar9 = (byte)uVar4 ^ bVar9 ^ *pbVar1;
      uVar4 = (uint)bVar9;
      uVar8 = uVar8 - 1;
    } while (uVar8 != 0);
    if (uVar5 + uVar6 * 2 < param_3) goto LAB_181272cec;
  }
  uVar10 = (ushort)bVar9;
  bVar33 = bVar33 + cVar32 + cVar34;
LAB_181272cfa:
  return (ushort)(byte)~bVar33 * 2 | uVar10 & 0xff;
}

