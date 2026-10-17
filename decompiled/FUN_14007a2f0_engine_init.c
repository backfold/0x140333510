// Function: 0x14007a2f0
// REA evidence_id: ev_690e2576b38681317d6f9fe0d8186eb06208e74da077af38f05b7c66b1c7a4a9
// Source: suddenattack.exe (sha256 1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741)

/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

bool FUN_14007a2f0(longlong param_1)

{
  char cVar1;
  undefined4 *puVar2;
  undefined8 *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  longlong lVar7;
  undefined8 uVar8;
  longlong lVar9;
  longlong lVar10;
  longlong lVar11;
  char *pcVar13;
  undefined8 *puVar14;
  undefined2 *puVar15;
  undefined1 *puVar16;
  undefined4 *puVar17;
  uint uVar18;
  byte bVar19;
  longlong *plVar20;
  ulonglong uVar21;
  undefined1 auStack_6c8 [32];
  char **local_6a8;
  byte local_698 [36];
  char local_674 [268];
  byte local_568 [36];
  char local_544 [268];
  longlong local_438 [20];
  undefined1 local_398 [160];
  char *local_2f8;
  char *local_2f0;
  undefined8 local_278;
  undefined8 uStack_270;
  undefined8 local_268;
  undefined1 auStack_260 [7];
  undefined4 uStack_259;
  undefined1 auStack_252 [265];
  undefined8 uStack_149;
  ulonglong local_38;
  longlong lVar12;
  
  local_38 = DAT_1403eef38 ^ (ulonglong)auStack_6c8;
  FUN_1402b8fb3(local_398,0,0xa0);
  local_278 = 0;
  uStack_270 = 0;
  local_268 = 0;
  _auStack_260 = 0;
  FUN_1400c96b0();
  lVar7 = (**(code **)(*DAT_1403fafa8 + 0x20))(DAT_1403fafa8,&DAT_140304898);
  *(uint *)(param_1 + 0x154) = (uint)(lVar7 != 0);
  uVar8 = (**(code **)(*DAT_1403fafa8 + 0x20))(DAT_1403fafa8,"world");
  *(undefined8 *)(param_1 + 0x160) = uVar8;
  FUN_140027500(0x1fd,"Find all the res trees.");
  uVar21 = 0;
  FUN_1402b8fb3(local_438,0,0xa0);
  uVar18 = 0;
  iVar4 = (**(code **)(*DAT_1403fafa8 + 0x10))();
  if (iVar4 != 1) {
    do {
      lVar7 = (**(code **)(*DAT_1403fafa8 + 0x18))(DAT_1403fafa8,uVar18);
      if (lVar7 != 0) {
        uVar8 = (**(code **)(*DAT_1403fafa8 + 0x18))(DAT_1403fafa8,uVar18);
        iVar4 = (*(code *)0x3d7838)(uVar8,&DAT_1403048c0);
        if (iVar4 == 0) {
          lVar7 = (**(code **)(*DAT_1403fafa8 + 0x18))(DAT_1403fafa8,uVar18 + 1);
          local_438[uVar21] = lVar7;
          iVar4 = (int)uVar21;
          uVar21 = (ulonglong)(iVar4 + 1);
          if (0x27 < iVar4 + 2U) break;
        }
      }
      uVar18 = uVar18 + 1;
      iVar4 = (**(code **)(*DAT_1403fafa8 + 0x10))();
    } while (uVar18 < iVar4 - 1U);
  }
  uVar18 = 0;
  plVar20 = local_438;
  do {
    if ((*plVar20 != 0) && (iVar4 = (*(code *)0x3d7a5c)(*plVar20,&DAT_1403048c8), iVar4 == 0))
    goto LAB_14007a47c;
    uVar18 = uVar18 + 1;
    plVar20 = plVar20 + 1;
  } while (uVar18 < 0x28);
  local_438[uVar21] = (longlong)&DAT_1403048d0;
  uVar21 = (ulonglong)((int)uVar21 + 1);
LAB_14007a47c:
  if (DAT_140409328 == 0) {
    local_438[uVar21] = (longlong)"engine.rez";
    uVar21 = (ulonglong)((int)uVar21 + 1);
  }
  bVar19 = 0;
  FUN_1402b8fb3((longlong)&uStack_149 + 1,0,0x104);
  (*(code *)0x3d5806)(0x104,(longlong)&uStack_149 + 1);
  puVar3 = &uStack_149;
  do {
    puVar14 = puVar3;
    puVar3 = (undefined8 *)((longlong)puVar14 + 1);
  } while (*(char *)((longlong)puVar14 + 1) != '\0');
  *(undefined8 *)((longlong)puVar14 + 1) = 0x2e2a5c656d61675c;
  *(undefined4 *)((longlong)puVar14 + 9) = 0x7a6572;
  lVar7 = (*(code *)0x3d78c8)((longlong)&uStack_149 + 1,local_698);
  if (-1 < lVar7) {
    do {
      iVar4 = (*(code *)0x3d782e)(local_674,&DAT_1403032bc);
      if ((iVar4 != 0) && (iVar4 = (*(code *)0x3d782e)(local_674,&DAT_1403048f4), iVar4 != 0)) {
        lVar10 = -1;
        do {
          lVar9 = lVar10 + 1;
          lVar12 = lVar10 + 1;
          lVar10 = lVar9;
        } while (local_674[lVar12] != '\0');
        if ((lVar9 != 0) && ((local_698[0] & 0x10) == 0)) {
          FID_conflict_sprintf_s
                    ((wchar_t *)(&DAT_1403f9b90 + (ulonglong)bVar19 * 0x80),0x80,
                     (wchar_t *)"game\\%s",local_674);
          local_438[uVar21] = (longlong)(&DAT_1403f9b90 + (ulonglong)bVar19 * 0x80);
          iVar4 = (int)uVar21;
          uVar21 = (ulonglong)(iVar4 + 1);
          if (0x27 < iVar4 + 2U) {
            FUN_1400275e0(0x1f8,"overflow rez file tree.");
            (*(code *)0x3d5edc)(0,"Rez Overflow!!!!!!!","ERROR",10);
            break;
          }
          bVar19 = bVar19 + 1;
        }
      }
      iVar4 = (*(code *)0x3d78da)(lVar7,local_698);
    } while (iVar4 == 0);
  }
  lVar7 = (**(code **)(*DAT_1403fafa8 + 0x20))(DAT_1403fafa8,"rez_dir");
  if (lVar7 != 0) {
    bVar19 = 0;
    FUN_1402b8fb3((longlong)&uStack_259 + 1,0,0x104);
    (*(code *)0x3d5806)(0x104);
    puVar15 = (undefined2 *)(auStack_260 + 7);
    do {
      pcVar13 = (char *)((longlong)puVar15 + 1);
      puVar15 = (undefined2 *)((longlong)puVar15 + 1);
    } while (*pcVar13 != '\0');
    *puVar15 = 0x5c;
    puVar16 = auStack_260 + 7;
    do {
      pcVar13 = puVar16 + 1;
      puVar16 = puVar16 + 1;
    } while (*pcVar13 != '\0');
    lVar10 = 0;
    do {
      cVar1 = *(char *)(lVar7 + lVar10);
      puVar16[lVar10] = cVar1;
      lVar10 = lVar10 + 1;
    } while (cVar1 != '\0');
    puVar2 = (undefined4 *)(auStack_260 + 7);
    do {
      puVar17 = puVar2;
      puVar2 = (undefined4 *)((longlong)puVar17 + 1);
    } while (*(char *)((longlong)puVar17 + 1) != '\0');
    *(undefined4 *)((longlong)puVar17 + 1) = 0x722e2a5c;
    *(undefined2 *)((longlong)puVar17 + 5) = 0x7a65;
    *(undefined1 *)((longlong)puVar17 + 7) = 0;
    lVar10 = (*(code *)0x3d78c8)((longlong)&uStack_259 + 1,local_568);
    if (-1 < lVar10) {
      do {
        iVar4 = (*(code *)0x3d782e)(local_544,&DAT_1403032bc);
        if ((iVar4 != 0) && (iVar4 = (*(code *)0x3d782e)(local_544,&DAT_1403048f4), iVar4 != 0)) {
          lVar12 = -1;
          do {
            lVar11 = lVar12 + 1;
            lVar9 = lVar12 + 1;
            lVar12 = lVar11;
          } while (local_544[lVar9] != '\0');
          if (lVar11 != 0) {
            if ((local_568[0] & 0x10) != 0) break;
            FUN_14005ec10(&DAT_1403f9b90 + (ulonglong)bVar19 * 0x80,"%s\\%s",lVar7,local_544);
            local_438[uVar21] = (longlong)(&DAT_1403f9b90 + (ulonglong)bVar19 * 0x80);
            iVar4 = (int)uVar21;
            uVar21 = (ulonglong)(iVar4 + 1);
            if (0x27 < iVar4 + 2U) {
              FUN_1400275e0(0x1f8,"overflow rez file tree.");
              (*(code *)0x3d5edc)(0,"Rez Overflow!!!!!!!1","ERROR",10);
              break;
            }
            bVar19 = bVar19 + 1;
          }
        }
        iVar4 = (*(code *)0x3d78da)(lVar10,local_568);
      } while (iVar4 == 0);
    }
  }
  lVar7 = (**(code **)(*DAT_1403fafa8 + 0x20))(DAT_1403fafa8,"noinput");
  if (lVar7 != 0) {
    *(undefined4 *)(param_1 + 0x814) = 0;
  }
  lVar7 = (**(code **)(*DAT_1403fafa8 + 0x20))(DAT_1403fafa8,"workingdir");
  if (lVar7 != 0) {
    (*(code *)0x3d57ee)(lVar7);
  }
  pcVar13 = (char *)(**(code **)(*DAT_1403fafa8 + 0x20))(DAT_1403fafa8,"config");
  local_2f8 = "autoexec.cfg";
  if (pcVar13 != (char *)0x0) {
    local_2f8 = pcVar13;
  }
  pcVar13 = (char *)(**(code **)(*DAT_1403fafa8 + 0x20))(DAT_1403fafa8,"display");
  local_2f0 = "display.cfg";
  if (pcVar13 != (char *)0x0) {
    local_2f0 = pcVar13;
  }
  lVar7 = (**(code **)(*DAT_1403fafa8 + 0x30))(DAT_1403fafa8,"+sounddll");
  if (lVar7 == 0) {
    *(undefined1 *)(param_1 + 0xa0c) = 0;
  }
  else {
    param_1 = param_1 - lVar7;
    pcVar13 = (char *)(lVar7 + 1);
    do {
      if (pcVar13[-1] == '\0') break;
      pcVar13[param_1 + 0xa0b] = pcVar13[-1];
      if (*pcVar13 == '\0') break;
      pcVar13[param_1 + 0xa0c] = *pcVar13;
      if (pcVar13[1] == '\0') break;
      pcVar13[param_1 + 0xa0d] = pcVar13[1];
      if (pcVar13[2] == '\0') break;
      pcVar13[param_1 + 0xa0e] = pcVar13[2];
      pcVar13 = pcVar13 + 4;
    } while ((longlong)(pcVar13 + (-1 - lVar7)) < 0x20);
  }
  iVar4 = (*(code *)0x3d54cc)();
  FUN_140027500(0x1fe,"initialize client manager.");
  local_6a8 = &local_2f8;
  iVar5 = FUN_14008fc10(DAT_1403fe648,local_438,uVar21,2);
  if (iVar5 == 0) {
    FUN_140163c20(DAT_1403fe648 + 0x37d8,&local_278,0x20);
    iVar6 = (*(code *)0x3d54cc)();
    FUN_1400b7f30("LithTech build %s initialized in %.2f seconds.\n",&local_278,
                  (double)((float)(uint)(iVar6 - iVar4) / 1000.0));
  }
  else {
    FUN_1400275e0(0x1f9,"Client manager initialize failure.");
  }
  return iVar5 == 0;
}


