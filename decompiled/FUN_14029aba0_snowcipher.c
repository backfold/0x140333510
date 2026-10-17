
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 *
FUN_14029aba0(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3,undefined4 param_4)

{
  int *piVar1;
  longlong *plVar2;
  int iVar3;
  longlong *plVar4;
  longlong lVar5;
  undefined4 uVar6;
  undefined8 uVar7;
  undefined1 auStack_88 [32];
  undefined4 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 *local_50;
  undefined8 *local_48;
  void *local_40;
  undefined8 *local_38;
  ulonglong local_30;
  
  local_30 = DAT_1403eef38 ^ (ulonglong)auStack_88;
  uVar7 = 0;
  local_68 = 0;
  *param_1 = Lambda::Stream::vftable;
  *param_1 = Lambda::CipherStream<Lambda::SnowCipher>::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  if (param_2[1] != 0) {
    LOCK();
    piVar1 = (int *)(param_2[1] + 8);
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  param_1[1] = *param_2;
  param_1[2] = param_2[1];
  local_50 = param_1;
  local_48 = param_2;
  local_38 = param_3;
  local_40 = operator_new(0xf8);
  if (local_40 != (void *)0x0) {
    uVar7 = FUN_14029ad10(local_40,param_3);
  }
  local_60 = 0;
  local_58 = 0;
  param_1[3] = uVar7;
  local_68 = 0;
  *(undefined4 *)(param_1 + 4) = param_4;
  *(undefined4 *)(param_1 + 5) = 0;
  uVar6 = (**(code **)(*(longlong *)param_1[1] + 0x18))();
  *(undefined4 *)((longlong)param_1 + 0x2c) = uVar6;
  param_1[6] = param_1[3];
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  *(undefined1 *)(param_1 + 10) = 0;
  *(undefined4 *)((longlong)param_1 + 0x54) = 0;
  *(bool *)((longlong)param_1 + 0x24) = *(int *)(param_1 + 4) != 0;
  plVar4 = (longlong *)param_2[1];
  if (plVar4 != (longlong *)0x0) {
    LOCK();
    plVar2 = plVar4 + 1;
    lVar5 = *plVar2;
    *(int *)plVar2 = (int)*plVar2 + -1;
    UNLOCK();
    if ((int)lVar5 == 1) {
      (**(code **)*plVar4)(plVar4);
      LOCK();
      piVar1 = (int *)((longlong)plVar4 + 0xc);
      iVar3 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar3 == 1) {
        (**(code **)(*plVar4 + 8))(plVar4);
      }
    }
  }
  *param_3 = Lambda::SnowCipher::vftable;
  FUN_1402acd10(param_3 + 1);
  *param_3 = Lambda::ICipher::vftable;
  return param_1;
}


