
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

void FUN_1402a9820(longlong *param_1,undefined8 param_2,int *param_3)

{
  longlong lVar1;
  undefined8 *puVar2;
  int iVar3;
  undefined8 uVar4;
  void *pvVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined8 *puVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  longlong lVar12;
  uint uVar13;
  undefined1 auStack_308 [32];
  undefined8 local_2e8;
  undefined4 local_2d8;
  undefined1 local_2d0 [8];
  char local_2c8;
  int *local_2c0 [2];
  int *local_2b0 [2];
  undefined1 *local_2a0 [2];
  undefined8 local_290;
  int *local_288;
  undefined8 local_280;
  int local_278;
  undefined4 local_274;
  undefined4 local_270;
  undefined4 local_26c;
  undefined4 local_268;
  int local_264;
  undefined8 *local_260;
  undefined8 *local_258;
  longlong lStack_250;
  undefined8 local_248;
  undefined8 uStack_240;
  undefined4 local_238;
  undefined4 uStack_234;
  undefined4 uStack_230;
  undefined4 uStack_22c;
  undefined4 local_228;
  undefined4 uStack_224;
  undefined4 uStack_220;
  undefined4 uStack_21c;
  longlong local_218;
  undefined1 *local_210;
  undefined1 local_208 [56];
  undefined1 local_1d0 [72];
  undefined1 local_188 [32];
  int local_168;
  undefined4 local_164;
  undefined4 local_160;
  undefined4 local_15c;
  undefined4 local_158;
  int local_154;
  undefined8 *local_150;
  undefined8 *local_148;
  undefined8 *puStack_140;
  undefined8 local_138;
  undefined8 uStack_130;
  undefined4 local_128;
  undefined4 uStack_124;
  undefined4 uStack_120;
  undefined4 uStack_11c;
  undefined4 local_118;
  undefined4 uStack_114;
  undefined4 uStack_110;
  undefined4 uStack_10c;
  undefined1 local_108 [40];
  undefined2 local_e0;
  undefined6 uStack_de;
  undefined8 local_d0;
  ulonglong local_c8;
  undefined1 local_c0 [32];
  undefined1 local_a0 [32];
  undefined1 local_80 [32];
  undefined1 local_60 [32];
  ulonglong local_40;
  
  local_40 = DAT_1403eef38 ^ (ulonglong)auStack_308;
  uVar13 = 0;
  local_2d8 = 0;
  lVar12 = *param_1;
  local_288 = param_3;
  local_280 = param_2;
  if ((ulonglong)(param_1[3] - param_1[1] >> 5) < (ulonglong)*(uint *)(lVar12 + 0x34)) {
    FUN_1402ab540(param_1 + 1);
    lVar12 = *param_1;
  }
  if (*(int *)(lVar12 + 0x34) != 0) {
    do {
      uVar4 = FUN_140290e00(param_2,&local_e0);
      FUN_1402a8600(local_c0,uVar4);
      if (7 < local_c8) {
        if (local_c8 * 2 + 2 < 0x1000) {
LAB_1402a9901:
          thunk_FUN_1402b909d();
          goto LAB_1402a9906;
        }
        lVar1 = *(longlong *)(CONCAT62(uStack_de,local_e0) + -8);
        if ((CONCAT62(uStack_de,local_e0) - lVar1) - 8U < 0x20) goto LAB_1402a9901;
        (*(code *)0x3d7636)(lVar1,local_c8 * 2 + 0x29);
LAB_1402a9c15:
        (*(code *)0x3d7636)();
LAB_1402a9c1c:
        (*(code *)0x3d7636)();
LAB_1402a9c23:
        (*(code *)0x3d7636)();
        break;
      }
LAB_1402a9906:
      local_d0 = 0;
      local_c8 = 7;
      local_e0 = 0;
      FUN_1402b18c0(&local_278,param_2);
      iVar3 = FUN_1402b15b0(&local_278);
      if (local_278 != iVar3) {
        FUN_14002f780(local_a0,&DAT_140354950);
        uVar4 = FUN_1402717c0(local_2d0,L"Exception",0,0x30);
        uVar6 = FUN_14028a5d0(local_2a0,L"Lambda::PackageHeaderLoader::LoadIndexTable",0,0x30);
        uVar7 = FUN_1402a8780(local_2b0,L"C:\\Git\\lapacker\\lib\\FileSystemLib\\PackageLoader.cpp",
                              0,0x30);
        uVar8 = FUN_1402717b0(local_2c0,&DAT_1403337a8,0,0x30);
        local_2e8 = uVar6;
        uVar6 = FUN_140276320(local_208,0xc2,uVar8,uVar7);
        uVar4 = FUN_140276270(local_1d0,uVar6,uVar4);
        FUN_1402a0290(local_108,uVar4,7,local_a0);
                    /* WARNING: Subroutine does not return */
        FUN_1402b8f9b(local_108,&DAT_1403d3758);
      }
      if (((longlong)local_258 - (longlong)local_260 >> 4 != 0) && (local_264 != *param_3)) {
        FUN_14002f780(local_80,&DAT_140354950);
        uVar4 = FUN_1402717c0(local_2d0,L"Exception",0,0x30);
        uVar6 = FUN_14028a5d0(local_2a0,L"Lambda::PackageHeaderLoader::LoadIndexTable",0,0x30);
        uVar7 = FUN_1402a8780(local_2b0,L"C:\\Git\\lapacker\\lib\\FileSystemLib\\PackageLoader.cpp",
                              0,0x30);
        uVar8 = FUN_1402717b0(local_2c0,&DAT_1403337b0,0,0x30);
        local_2e8 = uVar6;
        uVar6 = FUN_140276320(local_208,0xc6,uVar8,uVar7);
        uVar4 = FUN_140276270(local_1d0,uVar6,uVar4);
        FUN_1402a0290(local_108,uVar4,0x12,local_80);
                    /* WARNING: Subroutine does not return */
        FUN_1402b8f9b(local_108,&DAT_1403d3758);
      }
      lVar1 = param_1[2];
      if (lVar1 == param_1[3]) {
        FUN_1402a8a20(param_1 + 1,lVar1,local_c0);
      }
      else {
        local_218 = lVar1;
        FUN_1400612f0(lVar1,local_c0);
        param_1[2] = param_1[2] + 0x20;
      }
      local_210 = local_188;
      FUN_1400612f0(local_188,local_c0);
      puVar2 = local_258;
      puVar9 = local_260;
      local_2c0[0] = &local_168;
      local_168 = local_278;
      local_164 = local_274;
      local_160 = local_270;
      local_15c = local_26c;
      local_158 = local_268;
      local_154 = local_264;
      local_150 = (undefined8 *)0x0;
      local_148 = (undefined8 *)0x0;
      puStack_140 = (undefined8 *)0x0;
      if (local_260 != local_258) {
        uVar10 = (longlong)local_258 - (longlong)local_260 >> 4;
        if (0xfffffffffffffff < uVar10) {
LAB_1402a9e0b:
                    /* WARNING: Subroutine does not return */
          FUN_140027ec0();
        }
        uVar11 = uVar10 * 0x10;
        if (uVar11 < 0x1000) {
          if (uVar11 == 0) {
            local_150 = (undefined8 *)0x0;
          }
          else {
            local_150 = operator_new(uVar11);
          }
        }
        else {
          if (uVar11 + 0x27 <= uVar11) goto LAB_1402a9e0b;
          pvVar5 = operator_new(uVar11 + 0x27);
          if (pvVar5 == (void *)0x0) goto LAB_1402a9c15;
          local_150 = (undefined8 *)((longlong)pvVar5 + 0x27U & 0xffffffffffffffe0);
          local_150[-1] = pvVar5;
        }
        puStack_140 = local_150 + uVar10 * 2;
        local_148 = local_150;
        do {
          uVar4 = puVar9[1];
          *local_148 = *puVar9;
          local_148[1] = uVar4;
          local_148 = local_148 + 2;
          puVar9 = puVar9 + 2;
        } while (puVar9 != puVar2);
        local_290 = 0;
        param_3 = local_288;
      }
      local_138 = local_248;
      uStack_130 = uStack_240;
      local_128 = local_238;
      uStack_124 = uStack_234;
      uStack_120 = uStack_230;
      uStack_11c = uStack_22c;
      local_118 = local_228;
      uStack_114 = uStack_224;
      uStack_110 = uStack_220;
      uStack_10c = uStack_21c;
      local_2d8 = 1;
      FUN_1402a8800(param_1 + 4,local_2d0);
      local_2d8 = 0;
      local_2b0[0] = &local_168;
      if (local_150 != (undefined8 *)0x0) {
        uVar10 = (longlong)puStack_140 - (longlong)local_150 & 0xfffffffffffffff0;
        puVar9 = local_150;
        if (0xfff < uVar10) {
          uVar10 = uVar10 + 0x27;
          puVar9 = (undefined8 *)local_150[-1];
          if (0x1f < (ulonglong)((longlong)local_150 + (-8 - (longlong)puVar9))) goto LAB_1402a9c1c;
        }
        thunk_FUN_1402b909d(puVar9,uVar10);
        local_150 = (undefined8 *)0x0;
        local_148 = (undefined8 *)0x0;
        puStack_140 = (undefined8 *)0x0;
      }
      local_2a0[0] = local_188;
      FUN_14002f8c0(local_188);
      if (local_2c8 == '\0') {
        FUN_14002f780(local_60,&DAT_140354950);
        uVar4 = FUN_1402717c0(local_2d0,L"Exception",0,0x30);
        uVar6 = FUN_14028a5d0(local_2a0,L"Lambda::PackageHeaderLoader::LoadIndexTable",0,0x30);
        uVar7 = FUN_1402a8780(local_2b0,L"C:\\Git\\lapacker\\lib\\FileSystemLib\\PackageLoader.cpp",
                              0,0x30);
        uVar8 = FUN_1402717b0(local_2c0,&DAT_1403337b8,0,0x30);
        local_2e8 = uVar6;
        uVar6 = FUN_140276320(local_208,0xcd,uVar8,uVar7);
        uVar4 = FUN_140276270(local_1d0,uVar6,uVar4);
        FUN_1402a0290(local_108,uVar4,8,local_60);
                    /* WARNING: Subroutine does not return */
        FUN_1402b8f9b(local_108,&DAT_1403d3758);
      }
      if (local_260 != (undefined8 *)0x0) {
        uVar10 = lStack_250 - (longlong)local_260 & 0xfffffffffffffff0;
        puVar9 = local_260;
        if (0xfff < uVar10) {
          uVar10 = uVar10 + 0x27;
          puVar9 = (undefined8 *)local_260[-1];
          if (0x1f < (ulonglong)((longlong)local_260 + (-8 - (longlong)puVar9))) goto LAB_1402a9c23;
        }
        thunk_FUN_1402b909d(puVar9,uVar10);
        local_260 = (undefined8 *)0x0;
        local_258 = (undefined8 *)0x0;
        lStack_250 = 0;
      }
      FUN_14002f8c0(local_c0);
      uVar13 = uVar13 + 1;
      lVar12 = *param_1;
      param_2 = local_280;
    } while (uVar13 < *(uint *)(lVar12 + 0x34));
  }
  if (param_1[2] - param_1[1] >> 5 != (ulonglong)*(uint *)(lVar12 + 0x34)) {
    FUN_14002f780(local_a0,&DAT_140354950);
    uVar4 = FUN_1402717c0(local_2d0,L"Exception",0,0x30);
    uVar6 = FUN_14028a5d0(local_2a0,L"Lambda::PackageHeaderLoader::LoadIndexTable",0,0x30);
    uVar7 = FUN_1402a8780(local_2b0,L"C:\\Git\\lapacker\\lib\\FileSystemLib\\PackageLoader.cpp",0,
                          0x30);
    uVar8 = FUN_1402717b0(local_2c0,&DAT_1403337c0,0,0x30);
    local_2e8 = uVar6;
    uVar6 = FUN_140276320(local_208,0xd3,uVar8,uVar7);
    uVar4 = FUN_140276270(local_1d0,uVar6,uVar4);
    FUN_1402a0290(local_108,uVar4,9,local_a0);
                    /* WARNING: Subroutine does not return */
    FUN_1402b8f9b(local_108,&DAT_1403d3758);
  }
  return;
}


