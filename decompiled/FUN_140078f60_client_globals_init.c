// Function: 0x140078f60
// REA evidence_id: ev_af1e55a8d0005bfafbbc0ee107ce33553b41bf263eb13532b18512dd87f706b8
// Source: suddenattack.exe (sha256 1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741)

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined4 FUN_140078f60(undefined8 param_1)

{
  undefined4 *puVar1;
  char cVar2;
  int iVar3;
  longlong lVar4;
  code *pcVar5;
  longlong *plVar6;
  undefined8 uVar7;
  undefined1 *puVar8;
  char *pcVar9;
  undefined8 uVar10;
  undefined1 auStack_2b8 [32];
  undefined4 local_298;
  undefined4 local_290;
  undefined4 local_288;
  undefined4 local_280;
  undefined8 local_278;
  undefined8 local_270;
  undefined8 local_268;
  undefined8 local_260;
  undefined4 local_258;
  int local_254;
  int local_250;
  int local_24c;
  undefined4 *local_248;
  undefined8 local_240;
  undefined8 local_238;
  undefined1 *puStack_230;
  undefined8 local_228;
  undefined8 uStack_220;
  undefined8 local_218;
  undefined8 uStack_210;
  undefined8 local_208;
  undefined8 uStack_200;
  undefined8 local_1f8;
  undefined8 local_1e8;
  undefined8 uStack_1e0;
  undefined8 local_1d8;
  undefined8 uStack_1d0;
  undefined8 local_1c8;
  undefined8 uStack_1c0;
  undefined8 local_1b8;
  undefined8 uStack_1b0;
  int local_1a8;
  int local_1a4;
  int local_1a0;
  int local_19c;
  undefined1 local_198 [16];
  undefined4 local_188;
  undefined4 uStack_184;
  undefined4 local_180;
  undefined4 uStack_17c;
  undefined4 local_178;
  undefined1 local_174 [256];
  undefined2 local_74;
  undefined4 local_72;
  undefined2 local_6e;
  undefined8 local_68;
  undefined8 uStack_60;
  undefined8 local_58;
  undefined8 uStack_50;
  undefined8 local_48;
  undefined8 uStack_40;
  undefined8 local_38;
  undefined8 uStack_30;
  ulonglong local_28;
  
  local_28 = DAT_1403eef38 ^ (ulonglong)auStack_2b8;
  local_248 = &DAT_1403d98a0;
  local_1f8 = 0;
  local_258 = 0;
  local_1e8 = 0;
  uStack_1e0 = 0;
  local_1d8 = 0;
  uStack_1d0 = 0;
  local_1c8 = 0;
  uStack_1c0 = 0;
  local_238 = 0;
  puStack_230 = (undefined1 *)0x0;
  local_228 = 0;
  uStack_220 = 0;
  local_218 = 0;
  uStack_210 = 0;
  local_208 = 0;
  uStack_200 = 0;
  local_240 = param_1;
  FUN_1400bfea0("[CLIENT INIT] Init 7 - Client globals : 0x%x",&DAT_1403d98a0);
  FUN_1402b8fb3(&DAT_1403d98a0,0,0xa40);
  DAT_1403da2cc = 1;
  lVar4 = (**(code **)(*DAT_1403fafa8 + 0x20))(DAT_1403fafa8,"DebugStructBanks");
  local_254 = 0;
  if (lVar4 != 0) {
    DAT_14040ff28 = 1;
  }
  iVar3 = FUN_1402b9007(&DAT_1403d98b0,auStack_2b8);
  puVar1 = local_248;
  if (iVar3 == 0) {
    lVar4 = (**(code **)(*DAT_1403fafa8 + 0x20))(DAT_1403fafa8,"workingdir");
    if (lVar4 != 0) {
      (*(code *)0x3d57ee)(lVar4);
    }
    puVar1[0x205] = 1;
    FUN_140027500(0x1fb,"Initialize the system-dependent modules.");
    iVar3 = FUN_1400beb60();
    uVar10 = local_240;
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        FUN_1400275e0(0x1f7,"Unknown error initializing engine. ERROR CODE: -1");
        pcVar9 = "Unknown error initializing engine. ERROR CODE: -1";
LAB_1400790a4:
        (*(code *)0x3d5edc)(0,pcVar9,"Error",0);
        FUN_1400c0650();
        return 0xffffffff;
      }
      if (iVar3 != 2) {
        FUN_1400275e0(0x1f7,"Unknown error initializing engine. ERROR CODE: -2");
        pcVar9 = "Unknown error initializing engine. ERROR CODE: -2";
        goto LAB_1400790a4;
      }
    }
    *(undefined8 *)(puVar1 + 0x48) = local_240;
    *(char **)(puVar1 + 0x4a) = "__GH_Sudden_Attack__";
    *(char **)(puVar1 + 0x4c) = "SuddenAttack";
    FUN_140027500(0x1fc,"Create the main window.");
    FUN_1400991a0();
    puVar1[0x50] = 1;
    lVar4 = (**(code **)(*DAT_1403fafa8 + 0x20))(DAT_1403fafa8,"breakonerror");
    puVar1[0x4f] = (uint)(lVar4 != 0);
    local_238 = CONCAT44(local_238._4_4_,0xb);
    puStack_230 = &LAB_140078290;
    local_228 = 0;
    uStack_220 = *(undefined8 *)(puVar1 + 0x48);
    local_218 = (*(code *)0x3d5f34)(uVar10,0x80);
    uStack_210 = (*(code *)0x3d5f26)(0,0x7f00);
    local_208 = (*(code *)0x3d60cc)(4);
    uStack_200 = 0;
    local_1f8 = *(undefined8 *)(puVar1 + 0x4a);
    (*(code *)0x3d5dbe)(&local_238);
    uVar7 = (*(code *)0x3d5d1a)();
    (*(code *)0x3d5cec)(uVar7,&local_1b8);
    local_68 = 0;
    uStack_60 = 0;
    local_58 = 0;
    uStack_50 = 0;
    local_48 = 0;
    uStack_40 = 0;
    local_38 = 0;
    uStack_30 = 0;
    uVar7 = (**(code **)(*DAT_1403fafa8 + 0x30))(DAT_1403fafa8,"+MemberSN");
    FUN_1400741c0(&local_68,&DAT_140301ad0,uVar7);
    if ((char)local_68 != '\0') {
      FUN_140094950(DAT_1403fe648,&local_68);
    }
    iVar3 = (*(code *)0x3d58ba)("AutoOptionSetting","WindowMode",0,"./Profiles/Player.txt");
    local_260 = 0;
    DAT_1404104f8 = iVar3 != 0;
    local_268 = uVar10;
    local_270 = 0;
    local_278 = 0;
    uVar10 = 0x2ce0000;
    if (iVar3 == 0) {
      uVar10 = 0x92000000;
    }
    local_280 = 600;
    local_1b8 = 0;
    uStack_1b0 = 0x25800000320;
    local_288 = 800;
    local_290 = 0;
    local_298 = 0;
    uVar10 = (*(code *)0x3d5dd0)(((byte)DAT_1404104f8 ^ 1) << 0x12,*(undefined8 *)(puVar1 + 0x4a),
                                 *(undefined8 *)(puVar1 + 0x4c),uVar10);
    local_188 = 0x11c;
    uStack_184 = 0;
    *(undefined8 *)(puVar1 + 0x44) = uVar10;
    local_180 = 0;
    uStack_17c = 0;
    local_178 = 0;
    FUN_1402b8fb3(local_174,0,0x100);
    local_74 = 0;
    local_72 = 0;
    local_6e = 0;
    uVar10 = (*(code *)0x3d57d8)(0,2,3);
    uVar10 = (*(code *)0x3d57d8)(uVar10,1,3);
    uVar10 = (*(code *)0x3d57d8)(uVar10,0x20,3);
    uStack_184 = 6;
    local_180 = 0;
    local_74 = 1;
    iVar3 = (*(code *)0x3d58ee)(&local_188,0x23,uVar10);
    if (iVar3 != 0) {
      lVar4 = (*(code *)0x3d57c8)("SACefDll.dll");
      if (lVar4 == 0) {
        FUN_1400bfea0("[CLIENT INIT] SACefDll.dll load Fail");
      }
      pcVar5 = (code *)(*(code *)0x3d57b6)(lVar4,"GetInterface");
      if (pcVar5 == (code *)0x0) {
        FUN_1400bfea0("[CLIENT INIT] GetInterface load Fail");
      }
      plVar6 = (longlong *)(*pcVar5)();
      if (plVar6 == (longlong *)0x0) {
        FUN_1400bfea0("[CLIENT INIT] GetInterface() return null");
        DAT_1403da2d0 = plVar6;
      }
      else {
        DAT_1403da2d0 = plVar6;
        (**(code **)(*plVar6 + 8))(plVar6);
        (**(code **)(*DAT_1403da2d0 + 0x30))(DAT_1403da2d0,*(undefined8 *)(puVar1 + 0x44));
      }
    }
    (*(code *)0x3d5df2)(*(undefined8 *)(puVar1 + 0x44),1);
    DAT_1403e3c8c = 0;
    if (DAT_1404104f8 == '\0') {
      local_298 = 600;
      (*(code *)0x3d5d10)(local_198,0,0,800);
      puVar8 = local_198;
    }
    else {
      puVar8 = (undefined1 *)0x0;
    }
    (*(code *)0x3d5f0a)(puVar8);
    lVar4 = (**(code **)(*DAT_1403fafa8 + 0x28))(DAT_1403fafa8,"StartStandAlone");
    if ((lVar4 != 0) && (DAT_1403fe648 != 0)) {
      iVar3 = (*(code *)0x3d7a5c)(lVar4,&DAT_140303174);
      *(uint *)(DAT_1403fe648 + 0x32d0) = (uint)(iVar3 == 0);
    }
    lVar4 = (**(code **)(*DAT_1403fafa8 + 0x28))(DAT_1403fafa8,"service");
    if ((lVar4 != 0) &&
       ((((iVar3 = (*(code *)0x3d7a5c)(lVar4,"cj_internet"), iVar3 == 0 ||
          (iVar3 = (*(code *)0x3d7a5c)(lVar4,&DAT_140304db4), iVar3 == 0)) ||
         (iVar3 = (*(code *)0x3d7a5c)(lVar4,&DAT_140304db8), iVar3 == 0)) && (DAT_1403fe648 != 0))))
    {
      iVar3 = FUN_14008d9d0();
      if (iVar3 == 0) {
        FUN_1400bfea0("[ERROR] Read Param Reg");
        iVar3 = FUN_14008d870(DAT_1403fe648);
        if (iVar3 == 0) {
          FUN_1400bfea0("[ERROR] Read Param File");
        }
      }
      (*(code *)0x3d56b6)("./Param.in");
    }
    cVar2 = FUN_14007a2f0(puVar1);
    if (cVar2 != '\0') {
      FUN_140027500(0x201,"Start main game loop.");
      *puVar1 = 1;
      while (puVar1[0x46] == 0) {
        iVar3 = FUN_1400971c0(DAT_1403fe648);
        if (iVar3 != 0) {
          FUN_1400bfea0("[ENGINE] ERROR ClientMgr->Update() %d",iVar3);
          goto LAB_1400796a4;
        }
        if ((DAT_140409300 != 0) && (DAT_1403d99e4 == 0)) {
          (*(code *)0x3d5cec)(*(undefined8 *)(puVar1 + 0x44),&local_1a8);
          local_250 = (local_1a0 - local_1a8) / 2 + local_1a8;
          local_24c = (local_19c - local_1a4) / 2 + local_1a4;
          (*(code *)0x3d5ef8)(*(undefined8 *)(puVar1 + 0x44),&local_250);
        }
        local_298 = 1;
        iVar3 = (*(code *)0x3d5d9c)(&local_1e8,0,0,0);
        while (iVar3 != 0) {
          if ((int)uStack_1e0 == 0x12) {
            FUN_1400bfea0("[ENGINE] Recv WM_QUIT");
            local_258 = (undefined4)local_1d8;
            goto LAB_1400796a4;
          }
          if ((int)uStack_1e0 == 0x10) {
            pcVar9 = "[ENGINE] Recv WM_CLOSE";
LAB_1400795f6:
            FUN_1400bfea0(pcVar9);
          }
          else if ((int)uStack_1e0 == 2) {
            pcVar9 = "[ENGINE] Recv WM_DESTROY";
            goto LAB_1400795f6;
          }
          (*(code *)0x3d5d74)(&local_1e8);
          (*(code *)0x3d5d88)(&local_1e8);
          if ((puVar1[0x46] != 1) && (*(longlong **)(puVar1 + 0x28c) != (longlong *)0x0)) {
            (**(code **)(**(longlong **)(puVar1 + 0x28c) + 0x28))();
          }
          local_298 = 1;
          iVar3 = (*(code *)0x3d5d9c)(&local_1e8);
        }
        if (DAT_1403fafa0 != 0) {
          DAT_1403fafa0 = 0;
          (*(code *)0x3d5ea6)(DAT_1403d99b0);
        }
      }
      FUN_1400bfea0("[ENGINE] Recv QUIT MESSAGE");
      local_258 = 0;
    }
  }
  else {
    local_254 = 1;
  }
LAB_1400796a4:
  (*(code *)0x3d5f0a)(0);
  do {
    iVar3 = (*(code *)0x3d5eea)(1);
  } while (iVar3 < 0);
  FUN_140027500(0x204,"End main game loop.");
  *puVar1 = 0;
  FUN_1400bfea0("[ENGINE] ExitMsg: %s",puVar1 + 0x206);
  FUN_140096250(DAT_1403fe648);
  lVar4 = DAT_1403fe648;
  if (DAT_1403fe648 != 0) {
    FUN_140089490(DAT_1403fe648);
    thunk_FUN_1402b909d(lVar4,0x3fd0);
  }
  DAT_1403fe648 = 0;
  FUN_1400bfea0("[ENGINE] Release ClientMgr.");
  (*(code *)0x3d5de2)(*(undefined8 *)(puVar1 + 0x44));
  FUN_1400c0650();
  FUN_1400bfea0("[ENGINE] DSI Term.");
  if (local_254 != 0) {
    FUN_1400275e0(0x1fa,"Out Of Memory.");
    (*(code *)0x3d5df2)(*(undefined8 *)(puVar1 + 0x44),0);
    uVar10 = *(undefined8 *)(puVar1 + 0x4c);
    uVar7 = (*(code *)0x3d5d1a)();
    (*(code *)0x3d5edc)(uVar7,"Out of memory",uVar10,0);
  }
  return local_258;
}


