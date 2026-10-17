// REA session 28 — cshell.dll batch_decompile 0x0x180d5e9c0
// status: ok


/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

void FUN_180d5e9c0(uint *param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  longlong lVar7;
  int local_38 [4];
  ulonglong local_28;
  
  local_28 = DAT_1818e6cd8 ^ (ulonglong)local_38;
  uVar4 = *param_1;
  uVar1 = param_1[1];
  local_38[0] = 0x64363531;
  local_38[1] = 0x38376665;
  local_38[2] = 0x33323039;
  local_38[3] = 0x34636261;
  lVar7 = 2;
  uVar3 = 0xc6ef3720;
  do {
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 << 4) + uVar4 ^ local_38[uVar3 >> 0xb & 3] + uVar3);
    iVar2 = local_38[uVar3 + 0x647 & 3] + uVar3;
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar2 + 0x61c88647U);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 + 0x647 >> 0xb & 3] + 0x61c88647 + uVar3);
    iVar6 = local_38[uVar3 + 0x646 & 3] + uVar3;
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar6 + 0xc3910c8eU);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 + 0xc8e >> 0xb & 3] + -0x3c6ef372 + uVar3);
    iVar5 = local_38[uVar3 + 0x645 & 3] + uVar3;
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar5 + 0x255992d5U);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 + 0x12d5 >> 0xb & 3] + 0x255992d5 + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ uVar3 + 0xeb584e4d);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 - 0x6e4 >> 0xb & 3] + -0x78dde6e4 + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar2 + 0xe8ea9f63U);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 - 0x9d >> 0xb & 3] + -0x1715609d + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar6 + 0x4ab325aaU);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 + 0x5aa >> 0xb & 3] + 0x4ab325aa + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar5 + 0xac7babf1U);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 + 0xbf1 >> 0xb & 3] + -0x5384540f + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ uVar3 + 0x727a6769);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 + 0x1238 >> 0xb & 3] + 0xe443238 + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar2 + 0x700cb87fU);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 - 0x781 >> 0xb & 3] + 0x700cb87f + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar6 + 0xd1d53ec6U);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 - 0x13a >> 0xb & 3] + -0x2e2ac13a + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar5 + 0x339dc50dU);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 + 0x50d >> 0xb & 3] + 0x339dc50d + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ uVar3 + 0xf99c8085);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 + 0xb54 >> 0xb & 3] + -0x6a99b4ac + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar2 + 0xf72ed19bU);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 + 0x119b >> 0xb & 3] + -0x8d12e65 + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar6 + 0x58f757e2U);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 - 0x81e >> 0xb & 3] + 0x58f757e2 + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ iVar5 + 0xbabfde29U);
    uVar1 = uVar1 - ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                    local_38[uVar3 - 0x1d7 >> 0xb & 3] + -0x454021d7 + uVar3);
    uVar4 = uVar4 - ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ uVar3 + 0x80be99a1);
    lVar7 = lVar7 + -1;
    uVar3 = uVar3 + 0x1c886470;
  } while (lVar7 != 0);
  *param_2 = uVar4;
  param_2[1] = uVar1;
  return;
}


