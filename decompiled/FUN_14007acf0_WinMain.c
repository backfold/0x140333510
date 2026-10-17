// Function: 0x14007acf0
// REA evidence_id: ev_b69c573beffa565bf0de987c739b449c0c80cc2772d5c1e7e7c16ade5bac3f33
// Source: suddenattack.exe (sha256 1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741)

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulonglong FUN_14007acf0(undefined8 param_1,undefined8 param_2,longlong param_3)

{
  code *pcVar1;
  char cVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  void *pvVar6;
  longlong lVar7;
  longlong lVar8;
  char *pcVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  ulonglong uVar12;
  wchar_t *pwVar13;
  ulonglong uVar14;
  ulonglong uVar15;
  undefined1 auStack_e78 [32];
  undefined8 local_e58;
  undefined1 *local_e50;
  uint local_e48;
  uint local_e40;
  undefined1 local_e38 [4];
  undefined1 local_e34 [4];
  undefined4 local_e30;
  undefined8 local_e28;
  longlong local_e20;
  undefined8 local_e18;
  undefined2 local_e10;
  undefined2 local_e0e;
  undefined2 local_e0a;
  ushort local_e08;
  ushort local_e06;
  ushort local_e04;
  ushort local_e02;
  char *local_e00;
  undefined8 local_df0;
  ulonglong local_de8;
  undefined1 local_de0 [24];
  undefined2 local_dc8 [64];
  undefined8 local_d48;
  char *local_d38;
  char local_d30 [136];
  wchar_t *local_ca8;
  wchar_t local_ca0 [132];
  undefined1 local_b98 [320];
  undefined4 local_a58;
  undefined4 local_a54;
  undefined4 local_a50;
  undefined1 local_a4c;
  undefined4 local_a48;
  undefined4 local_a44;
  undefined4 local_a40;
  undefined4 local_a3c;
  undefined4 local_a38;
  undefined4 local_a30;
  undefined4 local_a2c;
  undefined4 local_a28;
  undefined4 local_a24;
  undefined4 local_a20;
  undefined2 local_a1c;
  undefined4 local_a18;
  undefined4 local_a14;
  undefined4 local_a10;
  undefined4 local_a0c;
  undefined4 local_a08;
  undefined2 local_a04;
  undefined4 local_a00;
  undefined4 local_9fc;
  undefined4 local_9f8;
  undefined4 local_9f4;
  undefined4 local_9f0;
  undefined4 local_9ec;
  undefined2 local_9e8;
  undefined4 local_9e0;
  undefined4 local_9dc;
  undefined4 local_9d8;
  undefined4 local_9d4;
  undefined4 local_9d0;
  undefined4 local_9cc;
  undefined2 local_9c8;
  undefined4 local_9c0;
  undefined4 local_9bc;
  undefined4 local_9b8;
  undefined4 local_9b4;
  undefined4 local_9b0;
  undefined4 local_9ac;
  undefined4 local_9a8;
  undefined4 local_9a4;
  undefined4 local_9a0;
  undefined4 local_99c;
  undefined4 local_998;
  undefined4 local_990;
  undefined4 local_98c;
  undefined4 local_988;
  undefined4 local_984;
  undefined4 local_980;
  undefined4 local_97c;
  undefined4 local_978;
  undefined4 local_974;
  undefined4 local_970;
  undefined4 local_96c;
  undefined4 local_968;
  undefined4 local_964;
  undefined4 local_960;
  undefined4 local_958;
  undefined4 local_954;
  undefined4 local_950;
  undefined4 local_94c;
  undefined4 local_948;
  undefined4 local_944;
  undefined4 local_940;
  undefined4 local_93c;
  undefined4 local_938;
  undefined4 local_934;
  undefined4 local_930;
  undefined4 local_92c;
  undefined4 local_928;
  undefined2 local_924;
  undefined4 local_920;
  undefined4 local_91c;
  undefined4 local_918;
  undefined4 local_914;
  undefined4 local_910;
  undefined4 local_90c;
  undefined4 local_908;
  undefined4 local_904;
  undefined4 local_900;
  undefined4 local_8fc;
  undefined4 local_8f8;
  undefined4 local_8f4;
  undefined4 local_8f0;
  undefined4 local_8ec;
  undefined4 local_8e8;
  undefined4 local_8e4;
  undefined4 local_8e0;
  undefined4 local_8dc;
  undefined4 local_8d8;
  undefined4 local_8d4;
  undefined4 local_8d0;
  undefined4 local_8cc;
  undefined4 local_8c8;
  undefined4 local_8c4;
  undefined4 local_8c0;
  undefined4 local_8bc;
  undefined4 local_8b8;
  undefined4 local_8b4;
  undefined4 local_8b0;
  char local_8a8 [144];
  undefined8 local_818;
  undefined8 uStack_810;
  undefined8 local_808;
  undefined8 uStack_800;
  undefined8 local_7f8;
  undefined8 uStack_7f0;
  undefined8 local_7e8;
  undefined8 uStack_7e0;
  undefined8 local_7d8;
  undefined8 uStack_7d0;
  undefined8 local_7c8;
  undefined8 uStack_7c0;
  undefined8 local_7b8;
  undefined8 uStack_7b0;
  undefined8 local_7a8;
  undefined8 uStack_7a0;
  undefined1 local_798 [272];
  undefined1 local_688 [256];
  undefined1 local_588 [272];
  undefined1 local_478 [272];
  undefined1 local_368 [272];
  undefined1 local_258 [528];
  ulonglong local_48;
  
  local_48 = DAT_1403eef38 ^ (ulonglong)auStack_e78;
  lVar7 = 0;
  local_e30 = 0;
  local_e20 = param_3;
  local_e18 = param_1;
  FUN_140088ec0(local_b98);
  FUN_1400909b0(local_b98);
  local_a00 = 0x410053;
  local_9fc = 0x6c0043;
  local_9f8 = 0x650069;
  local_9f4 = 0x74006e;
  local_9f0 = 0x6c002e;
  local_9ec = 0x67006f;
  local_9e8 = 0;
  if (DAT_1403fb028 == 0) {
    pvVar6 = operator_new(0x30);
    if (pvVar6 != (void *)0x0) {
      lVar7 = FUN_140061390(pvVar6);
    }
    LOCK();
    UNLOCK();
    DAT_1403fb028 = lVar7;
  }
  FUN_140062460(DAT_1403fb028,&local_a00);
  uVar3 = (*(code *)0x3d54cc)();
  (*(code *)0x3d7810)(uVar3);
  local_d48 = 0;
  local_dc8[0] = 0;
  (*(code *)0x3d77b4)(local_dc8,0x40,L"sa_kr",0xffffffffffffffff);
  local_d48._0_4_ = 3;
  FUN_1402b8fb3(local_258,0,0x208);
  (*(code *)0x3d581e)(0x104,local_258);
  (*(code *)0x3d77a8)(local_258,0x104,L"\\debugconfig.ini",0xffffffffffffffff);
  local_818 = 0;
  uStack_810 = 0;
  local_808 = 0;
  uStack_800 = 0;
  local_7f8 = 0;
  uStack_7f0 = 0;
  local_7e8 = 0;
  uStack_7e0 = 0;
  local_7d8 = 0;
  uStack_7d0 = 0;
  local_7c8 = 0;
  uStack_7c0 = 0;
  local_7b8 = 0;
  uStack_7b0 = 0;
  local_7a8 = 0;
  uStack_7a0 = 0;
  local_e50 = local_258;
  local_e58 = CONCAT44(local_e58._4_4_,0x40);
  (*(code *)0x3d58d2)(L"LiveAssistCrashDump",L"Behavior",0,&local_818);
  iVar4 = (*(code *)0x3d77c0)(L"SAVELOCAL_FULLDUMP_AND_SENDSERVER_MINIDUMP",&local_818);
  if (iVar4 == 0) {
    local_d48._0_4_ = 4;
  }
  local_a30 = 0x530043;
  local_a2c = 0x650068;
  local_a28 = 0x6c006c;
  local_a24 = 0x64002e;
  local_a20 = 0x6c006c;
  local_a1c = 0;
  local_a18 = 0x62004f;
  local_a14 = 0x65006a;
  local_a10 = 0x740063;
  local_a0c = 0x6c002e;
  local_a08 = 0x6f0074;
  local_a04 = 0;
  local_9c0 = 0x720065;
  local_9bc = 0x6f0072;
  local_9b8 = 0x6c0072;
  local_9b4 = 0x67006f;
  local_9b0 = 0x53005c;
  local_9ac = 0x430041;
  local_9a8 = 0x69006c;
  local_9a4 = 0x6e0065;
  local_9a0 = 0x2e0074;
  local_99c = 0x6f006c;
  local_998 = 0x67;
  local_a48 = 0x720065;
  local_a44 = 0x6f0072;
  local_a40 = 0x2e0072;
  local_a3c = 0x6f006c;
  local_a38 = 0x67;
  local_9e0 = 0x61006c;
  local_9dc = 0x6e0075;
  local_9d8 = 0x680063;
  local_9d4 = 0x720065;
  local_9d0 = 0x6c002e;
  local_9cc = 0x67006f;
  local_9c8 = 0;
  local_920 = 0x6c0062;
  local_91c = 0x630061;
  local_918 = 0x63006b;
  local_914 = 0x700069;
  local_910 = 0x650068;
  local_90c = 0x5c0072;
  local_908 = 0x6c0042;
  local_904 = 0x630061;
  local_900 = 0x43006b;
  local_8fc = 0x6c0061;
  local_8f8 = 0x36006c;
  local_8f4 = 0x2e0034;
  local_8f0 = 0x6f006c;
  local_8ec = 0x67;
  local_8e8 = 0x6c0062;
  local_8e4 = 0x630061;
  local_8e0 = 0x63006b;
  local_8dc = 0x700069;
  local_8d8 = 0x650068;
  local_8d4 = 0x5c0072;
  local_8d0 = 0x6c0042;
  local_8cc = 0x630061;
  local_8c8 = 0x43006b;
  local_8c4 = 0x700069;
  local_8c0 = 0x650068;
  local_8bc = 0x360072;
  local_8b8 = 0x2e0034;
  local_8b4 = 0x6f006c;
  local_8b0 = 0x67;
  local_990 = 0x6c0062;
  local_98c = 0x630061;
  local_988 = 0x63006b;
  local_984 = 0x700069;
  local_980 = 0x650068;
  local_97c = 0x5c0072;
  local_978 = 0x6c0042;
  local_974 = 0x630061;
  local_970 = 0x58006b;
  local_96c = 0x680063;
  local_968 = 0x2e0067;
  local_964 = 0x6f006c;
  local_960 = 0x67;
  local_958 = 0x6c0062;
  local_954 = 0x630061;
  local_950 = 0x63006b;
  local_94c = 0x700069;
  local_948 = 0x650068;
  local_944 = 0x5c0072;
  local_940 = 0x47004e;
  local_93c = 0x6c0043;
  local_938 = 0x650069;
  local_934 = 0x74006e;
  local_930 = 0x340036;
  local_92c = 0x6c002e;
  local_928 = 0x67006f;
  uVar12 = 0;
  local_924 = 0;
  (*(code *)0x3d5472)();
  (*(code *)0x3d5384)(local_d48._4_4_);
  (*(code *)0x3d52fc)(local_dc8,(undefined4)local_d48);
  (*(code *)0x3d535e)(&local_a30);
  (*(code *)0x3d535e)(&local_a18);
  (*(code *)0x3d5312)(&local_9c0);
  (*(code *)0x3d5312)(&local_a48);
  (*(code *)0x3d5312)(&local_9e0);
  (*(code *)0x3d5312)(L"vivox.log");
  (*(code *)0x3d5312)(L"debug.log");
  (*(code *)0x3d5312)(&local_920);
  (*(code *)0x3d5312)(&local_8e8);
  (*(code *)0x3d5312)(&local_990);
  (*(code *)0x3d5312)(&local_958);
  local_8a8[0] = '\0';
  local_8a8[1] = '\0';
  local_8a8[2] = '\0';
  local_8a8[3] = '\0';
  local_8a8[4] = '\0';
  local_8a8[5] = '\0';
  local_8a8[6] = '\0';
  local_8a8[7] = '\0';
  local_8a8[8] = '\0';
  local_8a8[9] = '\0';
  local_8a8[10] = '\0';
  local_8a8[0xb] = '\0';
  local_8a8[0xc] = '\0';
  local_8a8[0xd] = '\0';
  local_8a8[0xe] = '\0';
  local_8a8[0xf] = '\0';
  local_8a8[0x10] = '\0';
  local_8a8[0x11] = '\0';
  local_8a8[0x12] = '\0';
  local_8a8[0x13] = '\0';
  local_8a8[0x14] = '\0';
  local_8a8[0x15] = '\0';
  local_8a8[0x16] = '\0';
  local_8a8[0x17] = '\0';
  local_8a8[0x18] = '\0';
  local_8a8[0x19] = '\0';
  local_8a8[0x1a] = '\0';
  local_8a8[0x1b] = '\0';
  local_8a8[0x1c] = '\0';
  local_8a8[0x1d] = '\0';
  local_8a8[0x1e] = '\0';
  local_8a8[0x1f] = '\0';
  local_8a8[0x20] = '\0';
  local_8a8[0x21] = '\0';
  local_8a8[0x22] = '\0';
  local_8a8[0x23] = '\0';
  local_8a8[0x24] = '\0';
  local_8a8[0x25] = '\0';
  local_8a8[0x26] = '\0';
  local_8a8[0x27] = '\0';
  local_8a8[0x28] = '\0';
  local_8a8[0x29] = '\0';
  local_8a8[0x2a] = '\0';
  local_8a8[0x2b] = '\0';
  local_8a8[0x2c] = '\0';
  local_8a8[0x2d] = '\0';
  local_8a8[0x2e] = '\0';
  local_8a8[0x2f] = '\0';
  local_8a8[0x30] = '\0';
  local_8a8[0x31] = '\0';
  local_8a8[0x32] = '\0';
  local_8a8[0x33] = '\0';
  local_8a8[0x34] = '\0';
  local_8a8[0x35] = '\0';
  local_8a8[0x36] = '\0';
  local_8a8[0x37] = '\0';
  local_8a8[0x38] = '\0';
  local_8a8[0x39] = '\0';
  local_8a8[0x3a] = '\0';
  local_8a8[0x3b] = '\0';
  local_8a8[0x3c] = '\0';
  local_8a8[0x3d] = '\0';
  local_8a8[0x3e] = '\0';
  local_8a8[0x3f] = '\0';
  local_8a8[0x40] = '\0';
  local_8a8[0x41] = '\0';
  local_8a8[0x42] = '\0';
  local_8a8[0x43] = '\0';
  local_8a8[0x44] = '\0';
  local_8a8[0x45] = '\0';
  local_8a8[0x46] = '\0';
  local_8a8[0x47] = '\0';
  local_8a8[0x48] = '\0';
  local_8a8[0x49] = '\0';
  local_8a8[0x4a] = '\0';
  local_8a8[0x4b] = '\0';
  local_8a8[0x4c] = '\0';
  local_8a8[0x4d] = '\0';
  local_8a8[0x4e] = '\0';
  local_8a8[0x4f] = '\0';
  local_8a8[0x50] = '\0';
  local_8a8[0x51] = '\0';
  local_8a8[0x52] = '\0';
  local_8a8[0x53] = '\0';
  local_8a8[0x54] = '\0';
  local_8a8[0x55] = '\0';
  local_8a8[0x56] = '\0';
  local_8a8[0x57] = '\0';
  local_8a8[0x58] = '\0';
  local_8a8[0x59] = '\0';
  local_8a8[0x5a] = '\0';
  local_8a8[0x5b] = '\0';
  local_8a8[0x5c] = '\0';
  local_8a8[0x5d] = '\0';
  local_8a8[0x5e] = '\0';
  local_8a8[0x5f] = '\0';
  local_8a8[0x60] = '\0';
  local_8a8[0x61] = '\0';
  local_8a8[0x62] = '\0';
  local_8a8[99] = '\0';
  local_8a8[100] = '\0';
  local_8a8[0x65] = '\0';
  local_8a8[0x66] = '\0';
  local_8a8[0x67] = '\0';
  local_8a8[0x68] = '\0';
  local_8a8[0x69] = '\0';
  local_8a8[0x6a] = '\0';
  local_8a8[0x6b] = '\0';
  local_8a8[0x6c] = '\0';
  local_8a8[0x6d] = '\0';
  local_8a8[0x6e] = '\0';
  local_8a8[0x6f] = '\0';
  local_8a8[0x70] = '\0';
  local_8a8[0x71] = '\0';
  local_8a8[0x72] = '\0';
  local_8a8[0x73] = '\0';
  local_8a8[0x74] = '\0';
  local_8a8[0x75] = '\0';
  local_8a8[0x76] = '\0';
  local_8a8[0x77] = '\0';
  local_8a8[0x78] = '\0';
  local_8a8[0x79] = '\0';
  local_8a8[0x7a] = '\0';
  local_8a8[0x7b] = '\0';
  local_8a8[0x7c] = '\0';
  local_8a8[0x7d] = '\0';
  local_8a8[0x7e] = '\0';
  local_8a8[0x7f] = '\0';
  local_8a8[0x80] = 0;
  iVar4 = (*(code *)0x3d73ae)(local_de0);
  uVar11 = local_e18;
  lVar7 = local_e20;
  if (iVar4 == 0) {
    FUN_1402b8fb3(local_798,0,0x102);
    (*(code *)0x3d6368)(local_de0,local_798,0x80);
    (*(code *)0x3d5404)(L"GUID",local_798);
    local_d38 = local_d30;
    FUN_140077c40(&local_d38,local_798,3);
    pcVar9 = local_d38;
    do {
      cVar2 = *pcVar9;
      pcVar9[(longlong)(local_8a8 + -(longlong)local_d38)] = cVar2;
      pcVar9 = pcVar9 + 1;
    } while (cVar2 != '\0');
    if (local_d38 != local_d30) {
      (*(code *)0x3d7768)();
    }
  }
  local_e38[0] = 0;
  local_e00 = operator_new(0x20);
  local_df0 = 0x15;
  local_de8 = 0x1f;
  builtin_strncpy(local_e00,"errorlog\\SAClient.log",0x16);
  iVar4 = (*(code *)0x3d799a)(local_e00,0);
  if (iVar4 == 0) {
    local_e38[0] = 1;
  }
  (*(code *)0x3d543c)(L"IS_CLIENTLOG_EXISTS",local_e38);
  (*(code *)0x3d5332)(FUN_14007aba0);
  if (lVar7 != 0) {
    lVar8 = -1;
    do {
      lVar8 = lVar8 + 1;
    } while (*(char *)(lVar7 + lVar8) != '\0');
    if (lVar8 == 0) {
      FUN_1400bfea0("[ERROR] Setup Args");
      FUN_1400bfea0(">> No param");
      uVar12 = 0xffffffffffffffff;
      goto LAB_14007b9f9;
    }
  }
  cVar2 = FUN_140079d30(lVar7);
  if (cVar2 == '\0') {
    FUN_1400bfea0("[ERROR] Setup Args");
    FUN_1400bfea0(">> %s",lVar7);
    uVar12 = 0xffffffffffffffff;
  }
  else {
    (*(code *)0x3d58a4)(uVar11,local_588,0x104);
    local_e58 = 0;
    (*(code *)0x3d7820)(local_588,local_e34,local_478,0);
    (*(code *)0x3d5cae)(local_368,&DAT_1403047d0,local_e34,local_478);
    (*(code *)0x3d57ee)(local_368);
    pcVar9 = (char *)(**(code **)(*DAT_1403fafa8 + 0x30))(DAT_1403fafa8,"+CTool");
    if (((pcVar9 == (char *)0x0) || (*pcVar9 != '1')) || (pcVar9[1] != '\0')) {
      lVar7 = (**(code **)(*DAT_1403fafa8 + 0x30))(DAT_1403fafa8,"+SessionID");
      lVar8 = (**(code **)(*DAT_1403fafa8 + 0x30))(DAT_1403fafa8,"+NexonSN");
      local_e28 = 0;
      if (lVar8 != 0) {
        FUN_14007ba90(lVar8,&DAT_1403052d4,&local_e28);
      }
      if (lVar7 != 0) {
        (*(code *)0x3d5420)(L"NXSessionID",lVar7);
      }
      cVar2 = FUN_14002bbe0(lVar7,local_e28,local_8a8,4);
      if (cVar2 == '\0') {
        FUN_1400bfea0("[ERROR] Nexon Game Log System Initialize Failure.");
      }
      FUN_140027830(1);
      FUN_140027550(1,L"GameLogManager: initialize successful.");
      FUN_140027550(0x1f5,L"Sudden Attack Client Start.");
      (*(code *)0x3d5894)(&local_e10);
      local_e40 = (uint)local_e02;
      local_e48 = (uint)local_e04;
      local_e50 = (undefined1 *)CONCAT44(local_e50._4_4_,(uint)local_e06);
      local_e58 = CONCAT44(local_e58._4_4_,(uint)local_e08);
      FUN_1400bfea0("[CLIENT INIT] Start SuddenAttack V2.0 - %d/%02d/%02d %02d:%02d:%02d.%03d",
                    local_e10,local_e0e,local_e0a);
      local_a58 = 0x44495547;
      local_a54 = 0x59454b20;
      local_a50 = 0x7325203a;
      local_a4c = 0;
      FUN_1400bfea0(&local_a58,local_8a8);
      FUN_140027500(0x1f6,"Server Port");
      FUN_140027500(0x1f9,"CrashReport Start");
      if (lVar8 == 0) {
        pwVar13 = L"EMPTY";
      }
      else {
        local_ca8 = local_ca0;
        FUN_140077a20(&local_ca8,lVar8,3);
        pwVar13 = local_ca8;
      }
      (*(code *)0x3d5404)(DAT_1403da310,pwVar13);
      if ((lVar8 != 0) && (local_ca8 != local_ca0)) {
        (*(code *)0x3d7768)();
      }
      lVar7 = (**(code **)(*DAT_1403fafa8 + 0x30))(DAT_1403fafa8,"+ServerPort");
      FUN_1400bfea0("[CLIENT INIT] Start");
      uVar15 = uVar12;
      if (lVar7 == 0) {
LAB_14007b7b0:
        (*(code *)0x3d552e)();
        FUN_1400bfea0("[CLIENT INIT] Init 1 - ServerPort - %s",lVar7);
        iVar4 = (*(code *)0x3d7818)();
        pvVar6 = operator_new((ulonglong)(iVar4 % 0x500000 & 0xffff));
        FUN_1400bfea0("[CLIENT INIT] Init 2 - NGS Start");
        FUN_140027500(0x1f8,"NGS Start");
        FUN_1402b8fb3(local_688,0,0x100);
        uVar10 = FUN_14006df60();
        FUN_14006e070(uVar10);
        uVar10 = FUN_14006df60();
        _DAT_140409430 = FUN_14006e020(uVar10,0);
        if (_DAT_140409430 != 0) {
          uVar10 = FUN_14007aa20(_DAT_140409430);
          FUN_140077490(local_688,0xffffffffffffffff,&DAT_140305444,uVar10);
          FUN_1400275e0(0x1f6,"[NGS_ERROR] NGSStart(%s)",local_688);
        }
        FUN_1400bfea0("[CLIENT INIT] Init 3 - NGS End");
        FUN_14025ea00();
        _DAT_1403f9304 = (*(code *)0x3d54cc)();
        (*(code *)0x3d554a)(1);
        FUN_1400bfea0("[CLIENT INIT] Init 4 - CRASHREPORT Start");
        FUN_1400bfea0("[CLIENT INIT] Init 5 - CRASHREPORT End");
        FUN_140027500(0x1fa,"Start Game Client App.");
        FUN_1400bfea0("[CLIENT INIT] Init 6 - RunClientApp");
        uVar5 = FUN_140078f60(uVar11);
        if ((1 < (int)DAT_1404092f8) &&
           (DAT_1403f9300 = DAT_1403f9300 + 1, DAT_1403f9300 < DAT_1404092f8)) {
          do {
            DAT_1403f9300 = DAT_1403f9300 + 1;
            uVar5 = FUN_140078f60(uVar11);
          } while (DAT_1403f9300 < DAT_1404092f8);
        }
        FUN_1400bfea0("[TERM] CHackInfo Start");
        FUN_140096a00(local_b98);
        FUN_1400bfea0("[TERM] CHackInfo End");
        if (DAT_1403da2d0 != (longlong *)0x0) {
          FUN_1400bfea0("[TERM] ReleaseCEF Terminate Start.");
          (**(code **)(*DAT_1403da2d0 + 0x10))();
          DAT_1403da2d0 = (longlong *)0x0;
          FUN_1400bfea0("[TERM] ReleaseCEF Terminate End.");
        }
        FUN_1400bfea0("[TERM] Release CEF.");
        (*(code *)0x3d554a)(0);
        if (pvVar6 != (void *)0x0) {
          thunk_FUN_1402b909d(pvVar6);
        }
        uVar11 = FUN_140077960();
        FUN_1400623a0(uVar11);
        (*(code *)0x3d5568)();
        FUN_140027500(0x206,"finalize crash report");
        (*(code *)0x3d53e6)(0);
        (*(code *)0x3d53ac)(0);
        uVar12 = (ulonglong)uVar5;
      }
      else {
        do {
          uVar14 = uVar15 + 1;
          if (*(char *)(lVar7 + uVar15) != (&DAT_1403053dc)[uVar15]) goto LAB_14007b7b0;
          uVar15 = uVar14;
        } while (uVar14 != 5);
        FUN_1400797c0();
      }
      FUN_140027550(99,L"GameLogManager: finalized.");
      FUN_14002bde0(1);
    }
    else {
      (*(code *)0x3d56c4)(20000);
    }
  }
LAB_14007b9f9:
  if (0xf < local_de8) {
    uVar15 = local_de8 + 1;
    pcVar9 = local_e00;
    if (0xfff < uVar15) {
      uVar15 = local_de8 + 0x28;
      pcVar9 = *(char **)(local_e00 + -8);
      if ((char *)0x1f < local_e00 + (-8 - (longlong)pcVar9)) {
        (*(code *)0x3d7636)();
        pcVar1 = (code *)swi(3);
        uVar12 = (*pcVar1)();
        return uVar12;
      }
    }
    thunk_FUN_1402b909d(pcVar9,uVar15);
  }
  local_df0 = 0;
  local_de8 = 0xf;
  local_e00 = (char *)((ulonglong)local_e00 & 0xffffffffffffff00);
  FUN_140089880(local_b98);
  return uVar12 & 0xffffffff;
}


