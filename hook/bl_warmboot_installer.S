/* Installer: runs in the retained bootloader during the warm boot, copies the
 * 184-byte hook body into the stock SPI sOS and redirects a call into it.
 * Hook-agnostic -- it moves whatever body was planted at PAYLOAD_SOURCE.
 *
 * Helper (32 B) + tail (44 B) live in two zero caves TAIL_ORG apart; only
 * those two fragments are ever written, never the padding between them.
 * Body source is 184 bytes inside the optional control programming functions
 * at 0x196C4..1977B. Copy into stock-SPI-sOS 0x12CB8, patch the aligned word
 * at 0x9B28 LAST, then whole-D-cache maintenance + barrier and replay the
 * stock BL handoff.
 *
 * Card-tested on the default build (profile a). The other builds are
 * retargets that have never run on hardware; if the site word does not match,
 * the installer writes nothing and the card boots stock.
 */
.syntax unified
.cpu cortex-a5
.thumb

/* sOS-build dependent. Defaults are the tested build (BL 26565174 / sOS
 * 8168d633); the Makefile overrides them with --defsym for the others. */
.ifndef SOS_SITE
SOS_SITE = 0x9b28
.endif
.ifndef SOS_CAVE
SOS_CAVE = 0x12cb8
.endif
.ifndef BRANCH_TO_CAVE
BRANCH_TO_CAVE = 0xb8c6f009   /* B.W from SOS_SITE to SOS_CAVE */
.endif
.ifndef PAYLOAD_SOURCE
PAYLOAD_SOURCE = 0x196c4      /* BL span the helper copies into the cave */
.endif
.ifndef TAIL_ORG
TAIL_ORG = 0x124              /* tail cave address minus helper cave address */
.endif
.section .text,"ax",%progbits
.global installer_helper
.global installer_entry
installer_helper:
    ldr.n r1, site_address
    ldr r2, [r1]
    ldr.n r3, stock_site_word
    cmp r2,r3
    bne.n skip_install
    ldr.n r0,sos_cave
    ldr.n r1,payload_source
    movs r2,#184             /* must match the hook body length */
    blx 0x179c0              /* stock BL copy helper, same address on all builds */
    ldr.n r0,site_address
    ldr.n r1,branch_to_cave
    str r1,[r0]              /* redirect into the cave, LAST */
    blx 0x248                /* ROM cache maintenance + barrier */
skip_install:
    b.n installer_resume
    .org TAIL_ORG
installer_entry:
    push {r0-r5,lr}
    mrs r5,apsr
    b.n installer_helper
installer_resume:
    dsb sy
    msr apsr_nzcvq,r5
    pop.w {r0-r5,lr}
    b.w 0x17c64
    .balign 4
site_address: .word SOS_SITE
stock_site_word: .word 0xf0074620 /* complete MOV + first BL halfword */
sos_cave: .word SOS_CAVE
payload_source: .word PAYLOAD_SOURCE
branch_to_cave: .word BRANCH_TO_CAVE
