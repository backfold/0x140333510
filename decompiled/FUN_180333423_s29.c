
undefined8 FUN_1803333f0(undefined4 *param_1,undefined4 param_2,uint *param_3,undefined8 *param_4)

{
  undefined8 uVar1;
  undefined8 uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  
  if (((param_1 != (undefined4 *)0x0) && (param_3 != (uint *)0x0)) && (param_4 != (undefined8 *)0x0)
     ) {
    memset(param_1 + 1,0,0xb8);
    *param_1 = param_2;
    uVar1 = *param_4;
    uVar2 = param_4[1];
    param_1[0x29] = 0;
    param_1[0x2e] = 0;
    *(undefined8 *)(param_1 + 1) = uVar1;
    *(undefined8 *)(param_1 + 3) = uVar2;
    uVar10 = *param_3;
    uVar11 = param_3[2];
    uVar7 = param_3[1];
    uVar8 = param_3[3];
    uVar5 = uVar10 >> 8 & 0xff00ff00 | uVar10 << 0x18 | (uVar10 & 0xff00) << 8 | uVar10 >> 0x18;
    uVar4 = uVar11 >> 8 & 0xff00ff00 | uVar11 << 0x18 | (uVar11 & 0xff00) << 8 | uVar11 >> 0x18;
    uVar12 = uVar7 >> 8 & 0xff00ff00 | uVar7 << 0x18 | (uVar7 & 0xff00) << 8 | uVar7 >> 0x18;
    uVar3 = uVar8 >> 8 & 0xff00ff00 | uVar8 << 0x18 | (uVar8 & 0xff00) << 8 | uVar8 >> 0x18;
    uVar6 = uVar5 + 0x61c88647 + uVar4;
    uVar9 = (uVar12 - uVar3) + 0x9e3779b9;
    param_1[5] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar6 >> 0x18) * 4) ^
                 *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar6 >> 0x10 & 0xff) * 4) ^
                 *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar6 >> 8 & 0xff) * 4) ^
                 *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar6 & 0xff) * 4);
    uVar5 = uVar5 >> 8;
    uVar6 = (uVar7 >> 0x18) << 0x18 ^ uVar5;
    param_1[6] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar9 >> 0x18) * 4) ^
                 *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar9 >> 0x10 & 0xff) * 4) ^
                 *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar9 >> 8 & 0xff) * 4) ^
                 *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar9 & 0xff) * 4);
    uVar12 = uVar12 >> 8;
    uVar7 = uVar4 + 0xc3910c8d + uVar6;
    uVar9 = (uVar10 >> 0x18) << 0x18 ^ uVar12;
    uVar10 = (uVar9 - uVar3) + 0x3c6ef373;
    param_1[7] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar7 >> 0x18) * 4) ^
                 *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar7 >> 0x10 & 0xff) * 4) ^
                 *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar7 >> 8 & 0xff) * 4) ^
                 *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar7 & 0xff) * 4);
    uVar13 = uVar8 & 0xff ^ uVar4 << 8;
    param_1[8] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar10 >> 0x18) * 4) ^
                 *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar10 >> 0x10 & 0xff) * 4) ^
                 *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar10 >> 8 & 0xff) * 4) ^
                 *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar10 & 0xff) * 4);
    uVar10 = uVar6 + 0x8722191a + uVar13;
    uVar7 = uVar11 & 0xff ^ uVar3 << 8;
    uVar3 = (uVar9 - uVar7) + 0x78dde6e6;
    param_1[9] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar10 >> 0x18) * 4) ^
                 *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar10 >> 0x10 & 0xff) * 4) ^
                 *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar10 >> 8 & 0xff) * 4) ^
                 *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar10 & 0xff) * 4);
    uVar10 = uVar12 << 0x18 ^ uVar6 >> 8;
    param_1[10] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar3 >> 0x18) * 4) ^
                  *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar3 >> 0x10 & 0xff) * 4) ^
                  *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar3 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar3 & 0xff) * 4);
    uVar3 = uVar10 + 0xe443234 + uVar13;
    uVar5 = uVar5 << 0x18 ^ uVar9 >> 8;
    uVar12 = (uVar5 - uVar7) + 0xf1bbcdcc;
    param_1[0xb] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar3 >> 0x18) * 4) ^
                   *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar3 >> 0x10 & 0xff) * 4) ^
                   *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar3 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar3 & 0xff) * 4);
    uVar4 = (uVar8 & 0xff00) >> 8 ^ uVar13 << 8;
    param_1[0xc] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar12 >> 0x18) * 4) ^
                   *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar12 >> 0x10 & 0xff) * 4) ^
                   *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar12 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar12 & 0xff) * 4);
    uVar8 = uVar10 + 0x1c886467 + uVar4;
    uVar12 = (uVar11 & 0xff00) >> 8 ^ uVar7 << 8;
    uVar11 = (uVar5 - uVar12) + 0xe3779b99;
    param_1[0xd] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar8 >> 0x18) * 4) ^
                   *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar8 >> 0x10 & 0xff) * 4) ^
                   *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar8 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar8 & 0xff) * 4);
    param_1[0xe] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar11 >> 0x18) * 4) ^
                   *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar11 >> 0x10 & 0xff) * 4) ^
                   *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar11 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar11 & 0xff) * 4);
    uVar8 = (uVar9 >> 8) << 0x18 ^ uVar10 >> 8;
    uVar11 = (uVar6 >> 8) << 0x18 ^ uVar5 >> 8;
    uVar3 = uVar8 + 0x3910c8cd + uVar4;
    uVar6 = (uVar11 - uVar12) + 0xc6ef3733;
    param_1[0xf] = *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar3 >> 0x18) * 4) ^
                   *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar3 >> 0x10 & 0xff) * 4) ^
                   *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar3 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar3 & 0xff) * 4);
    uVar3 = (uVar7 & 0xffffff) >> 0x10 ^ uVar4 << 8;
    param_1[0x10] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar6 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar6 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar6 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar6 & 0xff) * 4);
    uVar7 = uVar8 + 0x72219199 + uVar3;
    uVar6 = (uVar13 & 0xffffff) >> 0x10 ^ uVar12 << 8;
    uVar9 = (uVar11 - uVar6) + 0x8dde6e67;
    param_1[0x11] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar7 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar7 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar7 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar7 & 0xff) * 4);
    param_1[0x12] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar9 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar9 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar9 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar9 & 0xff) * 4);
    uVar13 = (uVar5 >> 8) << 0x18 ^ uVar8 >> 8;
    uVar7 = (uVar10 >> 8) << 0x18 ^ uVar11 >> 8;
    uVar10 = uVar13 + 0xe4432331 + uVar3;
    uVar5 = (uVar7 - uVar6) + 0x1bbcdccf;
    param_1[0x13] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar10 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar10 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar10 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar10 & 0xff) * 4);
    uVar10 = (uVar12 & 0xffffff) >> 0x10 ^ uVar3 << 8;
    param_1[0x14] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar5 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar5 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar5 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar5 & 0xff) * 4);
    uVar9 = uVar13 + 0xc8864662 + uVar10;
    uVar5 = (uVar4 & 0xffffff) >> 0x10 ^ uVar6 << 8;
    uVar4 = (uVar7 - uVar5) + 0x3779b99e;
    param_1[0x15] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar9 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar9 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar9 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar9 & 0xff) * 4);
    param_1[0x16] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar4 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar4 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar4 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar4 & 0xff) * 4);
    uVar12 = (uVar11 >> 8) << 0x18 ^ uVar13 >> 8;
    uVar9 = (uVar8 >> 8) << 0x18 ^ uVar7 >> 8;
    uVar4 = (uVar9 - uVar5) + 0x6ef3733c;
    uVar11 = uVar12 + 0x910c8cc4 + uVar10;
    param_1[0x17] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar11 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar11 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar11 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar11 & 0xff) * 4);
    uVar8 = (uVar6 & 0xffffff) >> 0x10 ^ uVar10 << 8;
    param_1[0x18] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar4 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar4 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar4 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar4 & 0xff) * 4);
    uVar4 = uVar12 + 0x22191988 + uVar8;
    uVar11 = (uVar3 & 0xffffff) >> 0x10 ^ uVar5 << 8;
    uVar3 = (uVar9 - uVar11) + 0xdde6e678;
    param_1[0x19] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar4 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar4 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar4 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar4 & 0xff) * 4);
    param_1[0x1a] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar3 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar3 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar3 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar3 & 0xff) * 4);
    uVar3 = (uVar7 >> 8) << 0x18 ^ uVar12 >> 8;
    uVar13 = (uVar13 >> 8) << 0x18 ^ uVar9 >> 8;
    uVar7 = uVar3 + 0x4432330f + uVar8;
    uVar6 = (uVar13 - uVar11) + 0xbbcdccf1;
    param_1[0x1b] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar7 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar7 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar7 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar7 & 0xff) * 4);
    uVar4 = (uVar5 & 0xffffff) >> 0x10 ^ uVar8 << 8;
    param_1[0x1c] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar6 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar6 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar6 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar6 & 0xff) * 4);
    uVar5 = uVar3 + 0x8864661d + uVar4;
    uVar7 = (uVar10 & 0xffffff) >> 0x10 ^ uVar11 << 8;
    uVar10 = (uVar13 - uVar7) + 0x779b99e3;
    param_1[0x1d] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar5 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar5 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar5 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar5 & 0xff) * 4);
    param_1[0x1e] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar10 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar10 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar10 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar10 & 0xff) * 4);
    uVar10 = (uVar9 >> 8) << 0x18 ^ uVar3 >> 8;
    uVar5 = (uVar12 >> 8) << 0x18 ^ uVar13 >> 8;
    uVar6 = uVar10 + 0x10c8cc3a + uVar4;
    uVar9 = (uVar5 - uVar7) + 0xef3733c6;
    param_1[0x1f] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar6 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar6 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar6 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar6 & 0xff) * 4);
    uVar6 = (uVar11 & 0xffffff) >> 0x10 ^ uVar4 << 8;
    param_1[0x20] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar9 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar9 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar9 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar9 & 0xff) * 4);
    uVar4 = uVar10 + 0x21919873 + uVar6;
    uVar11 = (uVar8 & 0xffffff) >> 0x10 ^ uVar7 << 8;
    uVar7 = (uVar5 - uVar11) + 0xde6e678d;
    param_1[0x21] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar4 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar4 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar4 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar4 & 0xff) * 4);
    param_1[0x22] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar7 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar7 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar7 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar7 & 0xff) * 4);
    uVar6 = ((uVar13 >> 8) << 0x18 ^ uVar10 >> 8) + 0x432330e5 + uVar6;
    uVar10 = (((uVar3 >> 8) << 0x18 ^ uVar5 >> 8) - uVar11) + 0xbcdccf1b;
    param_1[0x23] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar6 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar6 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar6 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar6 & 0xff) * 4);
    param_1[0x24] =
         *(uint *)(&DAT_1814973b0 + (ulonglong)(uVar10 >> 0x18) * 4) ^
         *(uint *)(&DAT_181496fb0 + (ulonglong)(uVar10 >> 0x10 & 0xff) * 4) ^
         *(uint *)(&DAT_181496bb0 + (ulonglong)(uVar10 >> 8 & 0xff) * 4) ^
         *(uint *)(&DAT_1814967b0 + (ulonglong)(uVar10 & 0xff) * 4);
    return 1;
  }
  return 0;
}

