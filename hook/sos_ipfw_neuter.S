/* Neuter the SYS_DRV signature verdict for host-loaded IP firmware
 * (SMU, SDMA, MEC/RS64, IMU, RLC) as well as for TAs.
 *
 * Path, read out of signed .54: host GFX ring cmd 6 LOAD_IP_FW -> sOS
 * tee_cmd_dispatch (sub_147C4) case 6 at 0x14A74 -> sub_12A16, which issues
 * SYS_DRV service-1 opcode 0x1007 via SVC 0xF2. SYS_DRV .54 sub_E12D80 is the
 * 0x1007 leaf: 0xE12FE8 calls verify_image_signature (0xE20D7C), 0xE12FEC
 * copies the status to R4, 0xE12FEE rejects a bad signature with BNE.
 * Same shape as the TA verifier at 0xE12348 (opcode 0x1005, sub_E1217C),
 * which this hook also neuters so an unsigned TA still loads.
 *
 * Staged SYS_DRV image: VA 0xE1xxxx maps to T+0x1xxxx, T=*[stock-sOS 0x13394].
 *   T+0x12348 dword preimage 0xE9D6D12E, NOP the low halfword  (0x1005 TA)
 *   T+0x12FEC dword preimage 0xD1680004, NOP the high halfword (0x1007 IP FW)
 * Either preimage wrong -> neither site is written.
 *
 * This is the whole patch: it patches the staged SYS_DRV and installs nothing
 * else, so the signed .54 sOS stays byte-identical and nothing has to be
 * staged at boot.
 *
 * Card-tested on profile a: a GFX_FW_TYPE_RLC_P image with one bit flipped in
 * its RSA signature, which stock firmware rejects with 0xffff3072, was
 * accepted with ring status 0, and rejected again after a cold power cycle.
 * Removing the verdict is not a blanket pass: an image can still fail an
 * earlier container/keyring check, and a rejected LOAD_IP_FW is a known PSP
 * wedge (cold ATX after each try).
 */
.syntax unified
.cpu cortex-a5
.thumb

/* sOS-build dependent; the Makefile overrides these per build. */
.ifndef SOS_SITE
SOS_SITE = 0x9b28
.endif
.ifndef SOS_UNMAP
SOS_UNMAP = 0x10db8
.endif
.ifndef SOS_CACHE
SOS_CACHE = 0x5600       /* stock clean+invalidate + DSB helper */
.endif
.section .text,"ax",%progbits
.global sos_ipfw_neuter
sos_ipfw_neuter:
    push {r0-r4,lr}
    cmp r5,#0                /* SYS_DRV load succeeded */
    bne replay
    cmp r8,#10               /* FWID 10 = SYS_DRV */
    bne replay
    ldr r2,sys_offset
    add r2,r7                /* staged T+0x12348 */
    ldr r0,[r2]
    ldr r1,sys_preimage
    cmp r0,r1
    bne replay
    add.w r3,r2,#0xca4       /* staged T+0x12FEC */
    ldr r0,[r3]
    ldr r1,ipfw_preimage
    cmp r0,r1
    bne replay
    movw r0,#0xbf00
    strh r0,[r2]             /* 0x1005 TA reject    -> NOP */
    strh r0,[r3,#2]          /* 0x1007 IP-FW reject -> NOP */
    movs r0,#2
    movs r1,#1
    movw r3,#0xcaa           /* clean+invalidate spans both sites */
    bl SOS_CACHE
replay:
    pop.w {r0-r4,lr}
    mov r0,r4                /* displaced stock MOV from SOS_SITE */
    movw lr,#(SOS_SITE+7)    /* return just past the displaced pair, Thumb */
    b.w SOS_UNMAP            /* displaced BL target */
    .balign 4
sys_offset: .word 0x12348
sys_preimage: .word 0xe9d6d12e
ipfw_preimage: .word 0xd1680004
