// REA session 28 — cshell.dll batch_decompile 0x0x180d5ef00
// status: ok


/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* WARNING: Restarted to delay deadcode elimination for space: stack */

void FUN_180d5ef00(uint *param_1,uint *param_2)

{
  uint uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int local_28 [4];
  ulonglong local_18;
  
  local_18 = DAT_1818e6cd8 ^ (ulonglong)local_28;
  uVar3 = *param_1;
  uVar6 = 0;
  uVar1 = param_1[1];
  local_28[0] = 0x64363531;
  local_28[1] = 0x38376665;
  local_28[2] = 0x33323039;
  local_28[3] = 0x34636261;
  lVar2 = 2;
  do {
    uVar4 = uVar6 + 0x9e3779b9;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 << 4) + uVar1 ^ uVar6 + 0x64363531);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar4 >> 0xb & 3] + uVar4);
    uVar5 = uVar6 + 0x3c6ef372;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar4 & 3] + uVar4);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar5 >> 0xb & 3] + uVar5);
    uVar4 = uVar6 + 0xdaa66d2b;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar5 & 3] + uVar5);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar4 >> 0xb & 3] + uVar4);
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar4 & 3] + uVar4);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^
                    local_28[uVar6 + 0x78dde6e4 >> 0xb & 3] + uVar6 + 0x78dde6e4);
    uVar4 = uVar6 + 0x1715609d;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ uVar6 + 0xdd141c15);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar4 >> 0xb & 3] + uVar4);
    uVar5 = uVar6 + 0xb54cda56;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar4 & 3] + uVar4);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar5 >> 0xb & 3] + uVar5);
    uVar4 = uVar6 + 0x5384540f;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar5 & 3] + uVar5);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar4 >> 0xb & 3] + uVar4);
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar4 & 3] + uVar4);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^
                    local_28[uVar6 + 0xf1bbcdc8 >> 0xb & 3] + uVar6 + 0xf1bbcdc8);
    uVar4 = uVar6 + 0x8ff34781;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ uVar6 + 0x55f202f9);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar4 >> 0xb & 3] + uVar4);
    uVar5 = uVar6 + 0x2e2ac13a;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar4 & 3] + uVar4);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar5 >> 0xb & 3] + uVar5);
    uVar4 = uVar6 + 0xcc623af3;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar5 & 3] + uVar5);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar4 >> 0xb & 3] + uVar4);
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar4 & 3] + uVar4);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^
                    local_28[uVar6 + 0x6a99b4ac >> 0xb & 3] + uVar6 + 0x6a99b4ac);
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ uVar6 + 0xcecfe9dd);
    uVar4 = uVar6 + 0x8d12e65;
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar4 >> 0xb & 3] + uVar4);
    uVar5 = uVar6 + 0xa708a81e;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar4 & 3] + uVar4);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar5 >> 0xb & 3] + uVar5);
    uVar4 = uVar6 + 0x454021d7;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar5 & 3] + uVar5);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar4 >> 0xb & 3] + uVar4);
    uVar6 = uVar6 + 0xe3779b90;
    uVar3 = uVar3 + ((uVar1 >> 5 ^ uVar1 * 0x10) + uVar1 ^ local_28[uVar4 & 3] + uVar4);
    uVar1 = uVar1 + ((uVar3 >> 5 ^ uVar3 * 0x10) + uVar3 ^ local_28[uVar6 >> 0xb & 3] + uVar6);
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  *param_2 = uVar3;
  param_2[1] = uVar1;
  return;
}


