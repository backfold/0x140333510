
uint * FUN_1402abee0(uint *param_1,char *param_2,int param_3,uint param_4,uint param_5,uint param_6,
                    uint param_7)

{
  ulonglong uVar1;
  ulonglong uVar2;
  uint uVar3;
  uint uVar4;
  ulonglong uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint local_res20;
  uint local_a4;
  uint *local_a0;
  uint *local_98;
  ulonglong local_90;
  ulonglong local_80;
  ulonglong local_78;
  ulonglong local_68;
  uint *local_60;
  longlong local_48;
  
  param_1[0x28] = 0;
  param_1[0x29] = 0;
  param_1[0x2a] = 0;
  param_1[0x2b] = 0;
  param_1[0x2c] = 0;
  param_1[0x2d] = 0;
  param_1[0x26] = 0;
  uVar19 = (((int)*param_2 << 8 | (int)param_2[1]) << 8 | (int)param_2[2]) << 8 | (int)param_2[3];
  *param_1 = uVar19;
  if (param_3 == 0x80) {
    uVar16 = (((int)param_2[4] << 8 | (int)param_2[5]) << 8 | (int)param_2[6]) << 8 |
             (int)param_2[7];
    param_1[1] = uVar16;
    uVar11 = (((int)param_2[8] << 8 | (int)param_2[9]) << 8 | (int)param_2[10]) << 8 |
             (int)param_2[0xb];
    param_1[2] = uVar11;
    uVar7 = (((int)param_2[0xc] << 8 | (int)param_2[0xd]) << 8 | (int)param_2[0xe]) << 8 |
            (int)param_2[0xf];
    param_1[3] = uVar7;
    param_1[4] = ~uVar19;
    uVar16 = ~uVar16;
    param_1[5] = uVar16;
    uVar11 = ~uVar11;
    param_1[6] = uVar11;
    uVar7 = ~uVar7;
    param_1[7] = uVar7;
    uVar18 = *param_1;
    uVar6 = param_1[3];
    uVar14 = param_1[2];
    uVar15 = param_1[1];
    uVar19 = uVar18;
  }
  else {
    uVar15 = (((int)param_2[4] << 8 | (int)param_2[5]) << 8 | (int)param_2[6]) << 8 |
             (int)param_2[7];
    param_1[1] = uVar15;
    uVar14 = (((int)param_2[8] << 8 | (int)param_2[9]) << 8 | (int)param_2[10]) << 8 |
             (int)param_2[0xb];
    param_1[2] = uVar14;
    uVar6 = (((int)param_2[0xc] << 8 | (int)param_2[0xd]) << 8 | (int)param_2[0xe]) << 8 |
            (int)param_2[0xf];
    param_1[3] = uVar6;
    uVar18 = (((int)param_2[0x10] << 8 | (int)param_2[0x11]) << 8 | (int)param_2[0x12]) << 8 |
             (int)param_2[0x13];
    param_1[4] = uVar18;
    uVar16 = (((int)param_2[0x14] << 8 | (int)param_2[0x15]) << 8 | (int)param_2[0x16]) << 8 |
             (int)param_2[0x17];
    param_1[5] = uVar16;
    uVar11 = (((int)param_2[0x18] << 8 | (int)param_2[0x19]) << 8 | (int)param_2[0x1a]) << 8 |
             (int)param_2[0x1b];
    param_1[6] = uVar11;
    uVar7 = (((int)param_2[0x1c] << 8 | (int)param_2[0x1d]) << 8 | (int)param_2[0x1e]) << 8 |
            (int)param_2[0x1f];
    param_1[7] = uVar7;
    uVar7 = ~uVar7;
    uVar11 = ~uVar11;
    uVar16 = ~uVar16;
    uVar6 = ~uVar6;
    uVar14 = ~uVar14;
    uVar15 = ~uVar15;
    uVar19 = ~uVar19;
  }
  local_60 = param_1 + 0xd;
  local_98 = param_1 + 0xe;
  local_a0 = param_1 + 0xf;
  uVar8 = 0;
  param_1[8] = uVar19;
  param_1[9] = uVar15;
  param_1[10] = uVar14;
  param_1[0xb] = uVar6;
  param_1[0xc] = ~uVar18;
  *local_60 = uVar16;
  *local_98 = uVar11;
  *local_a0 = uVar7;
  *param_1 = *param_1 ^ param_4;
  uVar19 = *param_1;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  local_res20 = param_1[1];
  uVar18 = param_1[2];
  param_5 = param_5 ^ param_1[3];
  local_80 = (ulonglong)param_1[8];
  local_78 = (ulonglong)param_1[9];
  uVar2 = (ulonglong)param_1[10];
  local_a0 = (uint *)(ulonglong)param_1[0xb];
  local_a4 = param_1[4];
  param_6 = param_6 ^ param_1[5];
  local_98 = (uint *)(ulonglong)(param_7 ^ param_1[6]);
  local_90 = (ulonglong)param_1[7];
  local_60 = (uint *)0x0;
  uVar1 = (ulonglong)param_1[0xf];
  uVar6 = param_1[0xd];
  uVar5 = (ulonglong)param_1[0xe];
  local_68 = (ulonglong)param_1[0xc];
  local_48 = 2;
  do {
    uVar17 = *(uint *)(&DAT_1403ef1a0 + (uVar1 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403ef5a0 + ((ulonglong)local_a4 & 0xff) * 4) ^ (int)uVar1 << 8 ^
             local_a4 >> 8 ^ uVar6 ^ uVar19 + (int)local_60 ^ uVar8;
    uVar1 = (ulonglong)uVar17;
    uVar14 = (uint)uVar2;
    uVar8 = uVar14 + uVar8;
    uVar11 = *(uint *)(&DAT_1403ef9a0 + ((ulonglong)local_60 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + ((ulonglong)local_60 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + ((ulonglong)local_60 >> 0x10 & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + ((ulonglong)local_60 >> 8 & 0xff) * 4);
    uVar4 = (int)uVar5 << 8 ^
            *(uint *)(&DAT_1403ef1a0 + (uVar5 >> 0x18) * 4) ^
            *(uint *)(&DAT_1403ef5a0 + (ulonglong)(param_5 & 0xff) * 4) ^ uVar8 + uVar17 ^
            param_5 >> 8 ^ (uint)local_68 ^ uVar11;
    uVar5 = (ulonglong)uVar4;
    uVar15 = (uint)local_78;
    uVar11 = uVar15 + uVar11;
    uVar16 = *(uint *)(&DAT_1403ef9a0 + (ulonglong)(uVar8 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar8 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + (ulonglong)(uVar8 >> 0x10 & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar8 >> 8 & 0xff) * 4);
    uVar6 = *(uint *)(&DAT_1403ef1a0 + (ulonglong)(uVar6 >> 0x18) * 4) ^
            *(uint *)(&DAT_1403ef5a0 + (ulonglong)(uVar18 & 0xff) * 4) ^ uVar18 >> 8 ^ uVar6 << 8 ^
            uVar11 + uVar4 ^ uVar16 ^ (uint)local_a0;
    uVar7 = (uint)local_80;
    uVar16 = uVar7 + uVar16;
    uVar8 = *(uint *)(&DAT_1403ef9a0 + ((ulonglong)uVar11 & 0xff) * 4) ^
            *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar11 >> 0x18) * 4) ^
            *(uint *)(&DAT_1403f01a0 + ((ulonglong)(uVar11 >> 0x10) & 0xff) * 4) ^
            *(uint *)(&DAT_1403efda0 + ((ulonglong)(uVar11 >> 8) & 0xff) * 4);
    uVar3 = (uint)local_68 << 8 ^
            *(uint *)(&DAT_1403ef1a0 + (ulonglong)((uint)local_68 >> 0x18) * 4) ^
            *(uint *)(&DAT_1403ef5a0 + (ulonglong)(local_res20 & 0xff) * 4) ^ uVar16 + uVar6 ^
            local_res20 >> 8 ^ uVar8 ^ uVar14;
    local_68 = (ulonglong)uVar3;
    uVar11 = (uint)local_90;
    uVar8 = uVar11 + uVar8;
    uVar12 = *(uint *)(&DAT_1403ef9a0 + (ulonglong)(uVar16 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar16 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + (ulonglong)(uVar16 >> 0x10 & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar16 >> 8 & 0xff) * 4);
    uVar9 = uVar3 + uVar8 ^ uVar12 ^
            *(uint *)(&DAT_1403ef1a0 + (ulonglong)((uint)local_a0 >> 0x18) * 4) ^
            *(uint *)(&DAT_1403ef5a0 + (ulonglong)(uVar19 & 0xff) * 4) ^ (uint)local_a0 << 8 ^
            uVar19 >> 8 ^ uVar15;
    local_a0 = (uint *)(ulonglong)uVar9;
    uVar16 = (uint)local_98;
    uVar12 = uVar12 + uVar16;
    uVar13 = *(uint *)(&DAT_1403ef9a0 + ((ulonglong)uVar8 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar8 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + ((ulonglong)(uVar8 >> 0x10) & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + ((ulonglong)(uVar8 >> 8) & 0xff) * 4);
    uVar10 = *(uint *)(&DAT_1403ef1a0 + (uVar2 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403ef5a0 + (uVar1 & 0xff) * 4) ^ uVar14 << 8 ^ uVar17 >> 8 ^
             uVar12 + uVar9 ^ uVar13 ^ uVar7;
    uVar2 = (ulonglong)uVar10;
    uVar13 = param_6 + uVar13;
    uVar8 = *(uint *)(&DAT_1403ef9a0 + ((ulonglong)uVar12 & 0xff) * 4) ^
            *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar12 >> 0x18) * 4) ^
            *(uint *)(&DAT_1403f01a0 + ((ulonglong)(uVar12 >> 0x10) & 0xff) * 4) ^
            *(uint *)(&DAT_1403efda0 + ((ulonglong)(uVar12 >> 8) & 0xff) * 4);
    uVar12 = *(uint *)(&DAT_1403ef5a0 + (uVar5 & 0xff) * 4) ^
             *(uint *)(&DAT_1403ef1a0 + (local_78 >> 0x18) * 4) ^ uVar4 >> 8 ^ uVar15 << 8 ^
             uVar13 + uVar10 ^ uVar8 ^ uVar11;
    local_78 = (ulonglong)uVar12;
    uVar8 = local_a4 + uVar8;
    uVar14 = *(uint *)(&DAT_1403ef9a0 + (ulonglong)(uVar13 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar13 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + (ulonglong)(uVar13 >> 0x10 & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar13 >> 8 & 0xff) * 4);
    uVar13 = *(uint *)(&DAT_1403ef5a0 + (ulonglong)(uVar6 & 0xff) * 4) ^
             *(uint *)(&DAT_1403ef1a0 + (local_80 >> 0x18) * 4) ^ uVar6 >> 8 ^ uVar7 << 8 ^
             uVar8 + uVar12 ^ uVar14 ^ uVar16;
    local_80 = (ulonglong)uVar13;
    uVar14 = param_5 + uVar14;
    uVar15 = *(uint *)(&DAT_1403ef9a0 + (ulonglong)(uVar8 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar8 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + (ulonglong)(uVar8 >> 0x10 & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar8 >> 8 & 0xff) * 4);
    uVar7 = uVar3 >> 8 ^
            *(uint *)(&DAT_1403ef5a0 + (local_68 & 0xff) * 4) ^
            *(uint *)(&DAT_1403ef1a0 + (local_90 >> 0x18) * 4) ^ uVar14 + uVar13 ^ uVar11 << 8 ^
            param_6 ^ uVar15;
    local_90 = (ulonglong)uVar7;
    uVar15 = uVar18 + uVar15;
    uVar14 = *(uint *)(&DAT_1403ef9a0 + ((ulonglong)uVar14 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar14 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + (ulonglong)(uVar14 >> 0x10 & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar14 >> 8 & 0xff) * 4);
    uVar11 = uVar7 + uVar15 ^
             *(uint *)(&DAT_1403ef1a0 + ((ulonglong)local_98 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403ef5a0 + ((ulonglong)local_a0 & 0xff) * 4) ^ uVar16 << 8 ^ uVar9 >> 8
             ^ local_a4 ^ uVar14;
    local_98 = (uint *)(ulonglong)uVar11;
    uVar14 = local_res20 + uVar14;
    uVar15 = *(uint *)(&DAT_1403ef9a0 + ((ulonglong)uVar15 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar15 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + ((ulonglong)(uVar15 >> 0x10) & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar15 >> 8 & 0xff) * 4);
    param_6 = uVar11 + uVar14 ^
              *(uint *)(&DAT_1403ef1a0 + (ulonglong)(param_6 >> 0x18) * 4) ^
              *(uint *)(&DAT_1403ef5a0 + (uVar2 & 0xff) * 4) ^ param_6 << 8 ^ uVar10 >> 8 ^ param_5
              ^ uVar15;
    uVar15 = uVar19 + uVar15;
    uVar14 = *(uint *)(&DAT_1403ef9a0 + (ulonglong)(uVar14 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar14 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + (ulonglong)(uVar14 >> 0x10 & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar14 >> 8 & 0xff) * 4);
    local_a4 = *(uint *)(&DAT_1403ef5a0 + (local_78 & 0xff) * 4) ^
               *(uint *)(&DAT_1403ef1a0 + (ulonglong)(local_a4 >> 0x18) * 4) ^ uVar15 + param_6 ^
               uVar12 >> 8 ^ local_a4 << 8 ^ uVar18 ^ uVar14;
    uVar14 = uVar17 + uVar14;
    uVar15 = *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar15 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + (ulonglong)(uVar15 >> 0x10 & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar15 >> 8 & 0xff) * 4) ^
             *(uint *)(&DAT_1403ef9a0 + (ulonglong)(uVar15 & 0xff) * 4);
    param_5 = local_a4 + uVar14 ^
              *(uint *)(&DAT_1403ef5a0 + (local_80 & 0xff) * 4) ^
              *(uint *)(&DAT_1403ef1a0 + (ulonglong)(param_5 >> 0x18) * 4) ^ param_5 << 8 ^
              uVar13 >> 8 ^ local_res20 ^ uVar15;
    uVar15 = uVar4 + uVar15;
    uVar14 = *(uint *)(&DAT_1403ef9a0 + (ulonglong)(uVar14 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar14 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + (ulonglong)(uVar14 >> 0x10 & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar14 >> 8 & 0xff) * 4);
    uVar18 = *(uint *)(&DAT_1403ef5a0 + (local_90 & 0xff) * 4) ^
             *(uint *)(&DAT_1403ef1a0 + (ulonglong)(uVar18 >> 0x18) * 4) ^ uVar18 << 8 ^ uVar7 >> 8
             ^ param_5 + uVar15 ^ uVar14 ^ uVar19;
    uVar14 = uVar14 + uVar6;
    uVar15 = *(uint *)(&DAT_1403ef9a0 + (ulonglong)(uVar15 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar15 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + (ulonglong)(uVar15 >> 0x10 & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar15 >> 8 & 0xff) * 4);
    local_res20 = *(uint *)(&DAT_1403ef5a0 + ((ulonglong)local_98 & 0xff) * 4) ^
                  *(uint *)(&DAT_1403ef1a0 + (ulonglong)(local_res20 >> 0x18) * 4) ^ uVar11 >> 8 ^
                  local_res20 << 8 ^ uVar17 ^ uVar18 + uVar14 ^ uVar15;
    uVar15 = uVar15 + uVar3;
    uVar16 = *(uint *)(&DAT_1403ef9a0 + (ulonglong)(uVar14 & 0xff) * 4) ^
             *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar14 >> 0x18) * 4) ^
             *(uint *)(&DAT_1403f01a0 + ((ulonglong)(uVar14 >> 0x10) & 0xff) * 4) ^
             *(uint *)(&DAT_1403efda0 + (ulonglong)(uVar14 >> 8 & 0xff) * 4);
    uVar14 = uVar15 + local_res20 ^ uVar16;
    uVar19 = *(uint *)(&DAT_1403ef5a0 + ((ulonglong)param_6 & 0xff) * 4) ^
             *(uint *)(&DAT_1403ef1a0 + (ulonglong)(uVar19 >> 0x18) * 4) ^ param_6 >> 8 ^
             uVar19 << 8 ^ uVar14 ^ uVar4;
    uVar16 = uVar16 + uVar9;
    uVar8 = *(uint *)(&DAT_1403ef9a0 + (ulonglong)(uVar15 & 0xff) * 4) ^
            *(uint *)(&DAT_1403f05a0 + (ulonglong)(uVar15 >> 0x18) * 4) ^
            *(uint *)(&DAT_1403f01a0 + (ulonglong)(uVar15 >> 0x10 & 0xff) * 4) ^
            *(uint *)(&DAT_1403efda0 + ((ulonglong)(uVar15 >> 8) & 0xff) * 4);
    local_60 = (uint *)(ulonglong)uVar16;
    local_48 = local_48 + -1;
  } while (local_48 != 0);
  *param_1 = uVar19;
  param_1[1] = local_res20;
  param_1[2] = uVar18;
  param_1[3] = param_5;
  param_1[8] = uVar13;
  param_1[9] = uVar12;
  param_1[10] = uVar10;
  param_1[0xb] = uVar9;
  param_1[4] = local_a4;
  param_1[5] = param_6;
  param_1[6] = uVar11;
  param_1[7] = uVar7;
  param_1[0x12] = uVar16;
  param_1[0x13] = uVar8;
  param_1[0x10] = uVar14;
  param_1[0xf] = uVar17;
  param_1[0xd] = uVar6;
  param_1[0x11] = uVar16;
  param_1[0xe] = uVar4;
  param_1[0xc] = uVar3;
  param_1[0x24] = 0x10;
  FUN_1402ad020(param_1);
  return param_1;
}


