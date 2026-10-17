// Function: 0x140131010 (Ghidra-resolved start; queried at 0x140131444)
// REA evidence_id: ev_5e9fd862953c72643759971ed1d8d1fad2c922c9c122f174639f17b6831d214e
// Source: suddenattack.exe (sha256 1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741)

undefined8 FUN_140131010(longlong param_1,longlong param_2,ushort *param_3,undefined8 param_4)

{
  byte bVar1;
  ushort uVar2;
  undefined2 uVar3;
  uint uVar4;
  undefined4 *puVar5;
  byte bVar6;
  char cVar7;
  longlong lVar8;
  ushort uVar9;
  ushort uVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  undefined8 uVar13;
  ulonglong uVar14;
  float fVar15;
  undefined4 uVar16;
  undefined4 local_88;
  undefined4 uStack_84;
  
  uVar10 = *param_3;
  uVar2 = *(ushort *)(*(longlong *)(param_2 + 0x2b8) + 0x2b2);
  if (((*(byte *)(param_1 + 0xd0) & 8) == 0) && (*(longlong *)(param_1 + 0xb0) == param_2)) {
    uVar10 = uVar10 & 0xfbfb;
  }
  uVar9 = uVar10 & 0xbffd;
  if ((uVar2 & 2) == 0) {
    uVar9 = uVar10;
  }
  uVar10 = uVar9 & 0xfffb;
  if ((uVar2 & 4) == 0) {
    uVar10 = uVar9;
  }
  if ((*(char *)(param_2 + 0x11c) == '\x01') && ((uVar2 & 1) != 0)) {
    uVar10 = uVar10 & 0xffdf;
  }
  uVar9 = uVar10 | 0x20;
  if ((uVar10 & 0x2000) == 0) {
    uVar9 = uVar10;
  }
  uVar14 = 0;
  if ((uVar2 & 8) == 0) {
    if ((uVar2 & 0x10) == 0) {
      if ((uVar2 & 0x20) == 0) {
        if ((uVar2 & 0x40) != 0) {
          if ((uVar9 & 0x2000) == 0) {
            if ((uVar9 & 1) == 0) {
              cVar7 = FUN_1401425c0(DAT_14040dc50);
              if (cVar7 == '\0') {
                return 0;
              }
              uVar9 = uVar9 & 2;
            }
            else {
              uVar9 = uVar9 & 0x50db;
            }
          }
          else {
            uVar9 = uVar9 | 0x20;
          }
        }
      }
      else if (uVar9 != 0x721) {
        if ((uVar9 & 0x2000) == 0) {
          if ((uVar9 & 1) == 0) {
            uVar9 = 0;
          }
          else {
            uVar9 = uVar9 & 0x70f3;
          }
        }
        else {
          uVar9 = uVar9 | 0x20;
        }
      }
    }
    else if ((uVar9 != 0x721) && ((uVar9 & 0x81) == 0)) {
      uVar9 = uVar9 & 0xdfdf;
    }
  }
  else {
    uVar9 = uVar9 & 0xdfdf;
  }
  if ((uVar9 & 1) != 0) {
    uVar10 = uVar9 & 0xf5ff;
    uVar9 = uVar10 | 2;
    if (((*(uint *)(param_2 + 0xe8) & 0xffdb) != 0) || (*(int *)(param_2 + 0xf0) != 0)) {
      uVar9 = uVar10 | 10;
    }
  }
  uVar10 = uVar9 | 2;
  if ((uVar9 & 0x4000) == 0) {
    uVar10 = uVar9;
  }
  uVar12 = (ulonglong)uVar10;
  if (((uVar10 & 0x40) != 0) &&
     (((cVar7 = *(char *)(param_2 + 0x11c), cVar7 == '\0' || (cVar7 == '\t')) || (cVar7 == '\x05')))
     ) {
    uVar12 = (ulonglong)(uVar10 & 0xffbf);
  }
  uVar10 = (ushort)uVar12;
  if ((short)uVar10 < 0) {
    if ((*(uint *)(param_2 + 0xec) & 0x100) == 0) {
      uVar12 = (ulonglong)(uVar10 & 0x7fff);
    }
    uVar10 = (ushort)uVar12;
  }
  if (uVar10 == 0) {
    return 0;
  }
  FUN_14011df60(param_4,uVar12 & 0xff,8);
  uVar13 = 1;
  uVar11 = uVar14;
  if ((uVar12 & 0x8f00) != 0) {
    FUN_14011df60(param_4,1,1);
    uVar13 = 8;
    uVar11 = uVar12 >> 8;
  }
  FUN_14011df60(param_4,uVar11,uVar13);
  FUN_14011df60(param_4,*(undefined2 *)(param_2 + 0x118),0x10);
  if ((uVar12 & 1) != 0) {
    lVar8 = *(longlong *)(param_2 + 0x2b8);
    bVar1 = *(byte *)(param_2 + 0x11c);
    bVar6 = bVar1;
    if ((*(uint *)(lVar8 + 0x54) != 0) && (bVar6 = bVar1 | 0x40, 0xff < *(uint *)(lVar8 + 0x54))) {
      bVar6 = bVar1 | 0xc0;
    }
    FUN_14011df60(param_4,bVar6,8);
    uVar4 = *(uint *)(lVar8 + 0x54);
    if (uVar4 != 0) {
      uVar13 = 8;
      if (0xff < uVar4) {
        uVar13 = 0x10;
      }
      FUN_14011df60(param_4,uVar4,uVar13);
      FUN_14011e120(param_4,lVar8 + 0x48);
    }
    cVar7 = *(char *)(param_2 + 0x11c);
    if (cVar7 == '\x02') {
      FUN_14011e470(param_4,*(longlong *)(param_2 + 0x348) + 0xa4);
    }
    else if (cVar7 == '\t') {
      FUN_14011e470(param_4,*(longlong *)(param_2 + 0x348) + 0xa4);
      uVar3 = *(undefined2 *)(param_2 + 1000);
LAB_14013134f:
      FUN_14011df60(param_4,uVar3,0x10);
    }
    else if (cVar7 == '\x01') {
      cVar7 = FUN_140133430(param_2,param_4);
      if (cVar7 == '\0') {
        return 0;
      }
    }
    else if (cVar7 == '\x03') {
      uVar3 = *(undefined2 *)(*(longlong *)(*(longlong *)(param_2 + 0x2b8) + 0x78) + 0xc);
      goto LAB_14013134f;
    }
  }
  if (((ushort)uVar12 >> 0xb & 1) != 0) {
    if (*(char *)(param_2 + 0x11c) == '\x01') {
      cVar7 = FUN_140133430(param_2,param_4);
      if (cVar7 == '\0') {
        return 0;
      }
    }
    else if (*(char *)(param_2 + 0x11c) == '\x03') {
      FUN_14011df60(param_4,*(undefined2 *)
                             (*(longlong *)(*(longlong *)(param_2 + 0x2b8) + 0x78) + 0xc),0x10);
    }
  }
  if ((uVar12 & 0x2020) == 0) goto LAB_140131724;
  if (*(char *)(param_2 + 0x11c) != '\x01') {
    if (*(char *)(param_2 + 0x11c) == '\x03') {
      FUN_14011df00(param_4,*(undefined8 *)(param_2 + 0x368),0x40);
    }
    goto LAB_140131724;
  }
  if ((uVar2 & 8) == 0) {
    if ((uVar2 & 0x10) != 0) {
      FUN_14011df60(param_4,0,1);
      FUN_1401197d0(param_2,0xff);
      lVar8 = FUN_1401197d0(param_2,1);
      if (lVar8 == 0) {
        FUN_14011df60(param_4,0,0x10);
        FUN_14011df60(param_4,0,1);
        if (*(longlong *)(param_2 + 0x5a0) == 0) {
          FUN_1400bfea0("ERROR pModel->GetModelDB()");
        }
        else {
          uVar13 = FUN_1400ef7d0();
          FUN_1400bfea0("ERROR %s",uVar13);
        }
        FUN_1400bfea0("ERROR %s %d",
                      "D:\\Jenkins\\workspace\\workspace\\SA_QA_FINAL_BUILD\\svn_source\\Engine\\Runtime\\server\\src\\s_net.cpp"
                      ,0x408);
      }
      else {
        FUN_14011df60(param_4,*(undefined2 *)(lVar8 + 0x13c),0x10);
        FUN_14011df60(param_4,*(ushort *)(lVar8 + 0x28) >> 1 & 1,1);
        if ((uVar12 & 0x80) != 0) {
          FUN_14011df60(param_4,*(undefined2 *)(lVar8 + 0x140),0x10);
        }
      }
      lVar8 = FUN_1401197d0(param_2,2);
      if (lVar8 == 0) {
        FUN_14011df60(param_4,0,0x10);
        FUN_14011df60(param_4,0,1);
        if (*(longlong *)(param_2 + 0x5a0) == 0) {
          FUN_1400bfea0("ERROR pModel->GetModelDB()");
        }
        else {
          uVar13 = FUN_1400ef7d0();
          FUN_1400bfea0("ERROR %s",uVar13);
        }
        FUN_1400bfea0("ERROR %s %d",
                      "D:\\Jenkins\\workspace\\workspace\\SA_QA_FINAL_BUILD\\svn_source\\Engine\\Runtime\\server\\src\\s_net.cpp"
                      ,0x429);
      }
      else {
        FUN_14011df60(param_4,*(undefined2 *)(lVar8 + 0x13c),0x10);
        FUN_14011df60(param_4,*(ushort *)(lVar8 + 0x28) >> 1 & 1,1);
        if ((uVar12 & 0x80) != 0) {
          FUN_14011df60(param_4,*(undefined2 *)(lVar8 + 0x140),0x10);
        }
      }
      lVar8 = FUN_1401197d0(param_2,0x2c);
      uVar16 = 1;
      if ((lVar8 != 0) && (uVar10 = *(ushort *)(lVar8 + 0x13c), uVar10 != 0)) {
        FUN_14011df60(param_4,1,1);
        uVar14 = (ulonglong)uVar10;
        uVar16 = 0x10;
      }
      FUN_14011df60(param_4,uVar14,uVar16);
      goto LAB_140131724;
    }
    FUN_14011df60(param_4,1,1);
    lVar8 = FUN_1401197d0(param_2,0xff);
    if ((uVar2 & 0x20) != 0) {
      if (lVar8 == 0) {
        FUN_1400bfea0("ERROR %s %d",
                      "D:\\Jenkins\\workspace\\workspace\\SA_QA_FINAL_BUILD\\svn_source\\Engine\\Runtime\\server\\src\\s_net.cpp"
                      ,0x462);
      }
      else {
        FUN_14011df60(param_4,*(undefined2 *)(lVar8 + 0x13c),0x10);
        FUN_14011df60(param_4,*(ushort *)(lVar8 + 0x28) >> 1 & 1,1);
        FUN_14011df60(param_4,1,1);
        FUN_14011df60(param_4,*(undefined2 *)(lVar8 + 0x140),0x10);
      }
      lVar8 = FUN_1401197d0(param_2,1);
      if (lVar8 != 0) {
        FUN_14011df60(param_4,*(undefined2 *)(lVar8 + 0x13c),0x10);
      }
      goto LAB_140131724;
    }
    if (lVar8 == 0) {
      uVar13 = 0x48e;
      goto LAB_140131444;
    }
  }
  else {
    FUN_14011df60(param_4,1,1);
    lVar8 = FUN_1401197d0(param_2,0xff);
    if (lVar8 == 0) {
      uVar13 = 0x3d9;
LAB_140131444:
      FUN_1400bfea0("ERROR %s %d",
                    "D:\\Jenkins\\workspace\\workspace\\SA_QA_FINAL_BUILD\\svn_source\\Engine\\Runtime\\server\\src\\s_net.cpp"
                    ,uVar13);
      goto LAB_140131724;
    }
  }
  FUN_14011df60(param_4,*(undefined2 *)(lVar8 + 0x13c),0x10);
  FUN_14011df60(param_4,*(ushort *)(lVar8 + 0x28) >> 1 & 1,1);
  FUN_14011df60(param_4,0,1);
LAB_140131724:
  if ((uVar12 & 8) != 0) {
    FUN_14011df60(param_4,*(ushort *)(param_2 + 0xe8) & 0xffdb,0x10);
    FUN_14011df60(param_4,*(undefined4 *)(param_2 + 0xec),0x20);
    FUN_14011df60(param_4,*(undefined4 *)(param_2 + 0xf0),0x20);
  }
  if ((uVar12 & 0x40) != 0) {
    FUN_14011df60(param_4,*(undefined1 *)(param_2 + 0xf4),8);
    FUN_14011df60(param_4,*(undefined1 *)(param_2 + 0xf5),8);
    FUN_14011df60(param_4,*(undefined1 *)(param_2 + 0xf6),8);
    FUN_14011df60(param_4,*(undefined1 *)(param_2 + 0xf7),8);
    FUN_14011df60(param_4,*(undefined1 *)(param_2 + 0x11e),8);
    if (*(char *)(param_2 + 0x11c) == '\x04') {
      fVar15 = *(float *)(param_2 + 0x348);
      if (fVar15 <= 0.0) {
        fVar15 = 0.0;
      }
      FUN_14011df60(param_4,(int)fVar15 & 0xffff,0x10);
    }
  }
  if ((uVar12 & 0x10) != 0) {
    FUN_14011df60(param_4,*(undefined4 *)(param_2 + 0x10c),0x20);
    FUN_14011df60(param_4,*(undefined4 *)(param_2 + 0x110),0x20);
    if (*(char *)(param_2 + 0x11c) != '\x03') {
      FUN_14011df60(param_4,*(undefined4 *)(param_2 + 0x114),0x20);
    }
  }
  if ((uVar12 & 0x4202) != 0) {
    if (*(int *)(param_2 + 0x328) == 0x70996) {
      *(undefined4 *)(param_2 + 0x32c) = *(undefined4 *)(param_2 + 0x1f0);
      *(undefined4 *)(param_2 + 0x330) = *(undefined4 *)(param_2 + 500);
      *(undefined4 *)(param_2 + 0x334) = *(undefined4 *)(param_2 + 0x1f8);
    }
    uVar16 = *(undefined4 *)(param_2 + 0x334);
    uVar10 = *param_3;
    if ((uVar10 & 2) == 0) {
      local_88 = 0;
      uStack_84 = 0;
      uVar10 = uVar10 & 0xbfff | 2;
      uVar16 = 0;
    }
    else {
      uStack_84 = (undefined4)((ulonglong)*(undefined8 *)(param_2 + 0x32c) >> 0x20);
      uVar10 = uVar10 | 0x4000;
      local_88 = (undefined4)*(undefined8 *)(param_2 + 0x32c);
    }
    *param_3 = uVar10;
    if ((*(uint *)(param_2 + 0xe8) & 0x100) == 0) {
      if (*(int *)(param_2 + 0x328) == 0x70996) {
        *(undefined4 *)(param_2 + 300) = *(undefined4 *)(param_2 + 0x108);
        *(undefined4 *)(param_2 + 0x130) = *(undefined4 *)(param_2 + 0x1e0);
        *(undefined4 *)(param_2 + 0x134) = *(undefined4 *)(param_2 + 0x228);
      }
      FUN_1400e1ac0(param_4);
    }
    else {
      if (*(int *)(param_2 + 0x328) == 0x70996) {
        *(undefined4 *)(param_2 + 300) = *(undefined4 *)(param_2 + 0x108);
        *(undefined4 *)(param_2 + 0x130) = *(undefined4 *)(param_2 + 0x1e0);
        *(undefined4 *)(param_2 + 0x134) = *(undefined4 *)(param_2 + 0x228);
      }
      FUN_1401331b0(param_4);
      if ((*(uint *)(param_2 + 0xec) & 0x800000) != 0) {
        local_88 = 0;
        uStack_84 = 0;
        uVar16 = 0;
      }
      FUN_14011df60(param_4,local_88,0x20);
      FUN_14011df60(param_4,uStack_84,0x20);
      FUN_14011df60(param_4,uVar16,0x20);
    }
  }
  if ((uVar12 & 0x404) != 0) {
    if ((*(uint *)(param_2 + 0xe8) & 0x100) == 0) {
      FUN_1400dfc10(param_4,param_2 + 0x178);
    }
    else {
      FUN_14011e010(param_4,param_2 + 0x178,0x80);
    }
  }
  if ((uVar12 & 0x100) != 0) {
    for (puVar5 = *(undefined4 **)(param_2 + 0xf8); puVar5 != (undefined4 *)0x0;
        puVar5 = *(undefined4 **)(puVar5 + 0xc)) {
      FUN_14011df60(param_4,*(undefined2 *)(puVar5 + 10),0x10);
      FUN_14011df60(param_4,puVar5[0xb],0x20);
      FUN_14011df60(param_4,*puVar5,0x20);
      FUN_14011df60(param_4,puVar5[1],0x20);
      FUN_14011df60(param_4,puVar5[2],0x20);
      FUN_1400dfc10(param_4,puVar5 + 3);
    }
    FUN_14011df60(param_4,0xffff,0x10);
  }
  return 1;
}


