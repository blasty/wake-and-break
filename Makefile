# Build and verify everything wakebreak.py needs.
#
#   make              build any missing installer + source_ipfw blob
#   make rebuild      discard the shipped blobs and reassemble them all
#   make verify       size + sha256 of every file wakebreak.py reads
#   make selftest     offline checks: manifests, blob bindings, identify.py
#   make tarball      wake-and-break.tar.gz of the tracked files
#   make clean        remove build/ and dist/
#
# Needs arm-none-eabi-{as,ld,objcopy} only for `make`; verify/selftest and
# running the plant do not. Nothing here touches a device.
#
# Reproduces the card-tested bytes with GNU binutils 2.43.1. If the toolchain
# is not on PATH, point CROSS at its prefix, e.g. on macOS/devkitARM:
#   make CROSS=/opt/devkitpro/devkitARM/bin/arm-none-eabi-

CROSS   ?= arm-none-eabi-
AS      := $(CROSS)as
LD      := $(CROSS)ld
OBJCOPY := $(CROSS)objcopy
PYTHON  ?= python3
ASFLAGS := -mcpu=cortex-a5

HOOK  := hook
BUILD := build

INSTALLER_SRC := $(HOOK)/bl_warmboot_installer.S
IPFW_SRC      := $(HOOK)/sos_ipfw_neuter.S
INSTALLER_ENTRY := installer_entry
IPFW_ENTRY      := sos_ipfw_neuter

# --- per-profile geometry; see PROFILES in wakebreak.py ----------------------
# Link bases are where the code *runs*, not where the bytes are written.
# "base" is profile a, whose blobs carry no filename suffix.
PROFILES := base sosb sosc sosd
sfx = $(if $(filter base,$(1)),,_$(1))

IBASE_base := 0x1a070
IDEFS_base :=
IBASE_sosb := 0x1a070
IDEFS_sosb := --defsym SOS_SITE=0x9b48 --defsym SOS_CAVE=0x12cd8
IBASE_sosc := 0x1a024
IDEFS_sosc := --defsym SOS_SITE=0x99ac --defsym SOS_CAVE=0x12ab8 \
              --defsym BRANCH_TO_CAVE=0xb884f009 \
              --defsym PAYLOAD_SOURCE=0x1968c --defsym TAIL_ORG=0x110
IBASE_sosd := 0x1a104
IDEFS_sosd := --defsym SOS_SITE=0x9c80 --defsym SOS_CAVE=0x132a4 \
              --defsym BRANCH_TO_CAVE=0xbb10f009 \
              --defsym PAYLOAD_SOURCE=0x19780 --defsym TAIL_ORG=0xa0

# source_ipfw: link base = sOS cave, pad-to = base + 184 (0xb8)
PBASE_base := 0x12cb8
PPAD_base  := 0x12d70
PDEFS_base :=
PBASE_sosb := 0x12cd8
PPAD_sosb  := 0x12d90
PDEFS_sosb := --defsym SOS_SITE=0x9b48 --defsym SOS_UNMAP=0x10dd8
PBASE_sosc := 0x12ab8
PPAD_sosc  := 0x12b70
PDEFS_sosc := --defsym SOS_SITE=0x99ac --defsym SOS_UNMAP=0x10bc8 \
              --defsym SOS_CACHE=0x54f4
PBASE_sosd := 0x132a4
PPAD_sosd  := 0x1335c
PDEFS_sosd := --defsym SOS_SITE=0x9c80 --defsym SOS_UNMAP=0x1136c \
              --defsym SOS_CACHE=0x5688

# --- pinned bytes ------------------------------------------------------------
# installer*.bin are the card-tested artifacts (the installer is hook-agnostic).
# source_ipfw.bin is the card-tested profile-a blob; the _sos[bcd] variants have
# never run on hardware and these pins only freeze what this toolchain produced.
SHA_installer.bin  := 6365d11439dacffe5a1e9d5ead097359c8d8f90b182e6d198d639d15adeb6fac
SHA_installer_sosb.bin := 6b43a487209368da8ffc20401156e4c5d4879305d8bdd695ca2544c74815d94e
SHA_installer_sosc.bin := 94de0fa2427401aa16c99d68a2123421cdd9f825c95de78eb9e2ce5d9cd3b963
SHA_installer_sosd.bin := 37cc6ded72379e6dc9a8891022c2e6fa0d151a02d5f7435272de84b6f2ea49de
SHA_source_ipfw.bin := 448ebe3ab89c4af8f9a443097cdb26f48ff986947331ec31a1bed5fcb329fc53
SHA_source_ipfw_sosb.bin := 06804c7629a427a3e3fc54f343e8af1ce3ea6c28ef43be11563c6b65c96ba3e1
SHA_source_ipfw_sosc.bin := 9da7c0a79fb69ac9ea8b952fabcde5c90666d65795641d70e1f2fe7d5e49bd6d
SHA_source_ipfw_sosd.bin := 2558c9208a8adad45589f309d25ca3d782d0a82b7026cacb3d4c29ca93906793
SHA_source_stock.bin := 81cfb49dd6289a4b4b9fb1f5f2e5c45a0240e582e121870e996b4a1b1e71d666
SHA_source_stock_sosc.bin := 858cbd1d20026871da0347112dc9c166e388e900989813eb9fdd1e4dd0196331
SHA_source_stock_sosd.bin := aa0eaa6002659d5f2efbb0467b091d6eacacecb15d39068d7735af3726708466
SHA_asd_33-0-0-163_18debcc4.bin := 66244f871096e55ff7585d6bf4078ea353d6287dd588a6af3599b6e9aa901d4c
SHA_ta_22-0-0-77_7c426e7f.bin := 933aa88e53e4f80efa152a82ac6be7abecd6ab15c0fda6f0207d842ec5521551

# TAIL_ORG differs per profile, so the installer images differ in length; only
# the 32-byte helper and 44-byte tail inside them are ever written.
SIZE_installer.bin := 336
SIZE_installer_sosb.bin := 336
SIZE_installer_sosc.bin := 316
SIZE_installer_sosd.bin := 204
SIZE_source_ipfw.bin := 184
SIZE_source_ipfw_sosb.bin := 184
SIZE_source_ipfw_sosc.bin := 184
SIZE_source_ipfw_sosd.bin := 184

BLOBS := $(foreach p,$(PROFILES),$(HOOK)/installer$(call sfx,$(p)).bin \
                                 $(HOOK)/source_ipfw$(call sfx,$(p)).bin)
# Stock preimages are not code: each is a span cut from that build's own SPI
# bootloader image. Profiles a and b share one.
STOCKS := $(HOOK)/source_stock.bin $(HOOK)/source_stock_sosc.bin \
          $(HOOK)/source_stock_sosd.bin
FIRMWARE := firmware/asd_33-0-0-163_18debcc4.bin firmware/ta_22-0-0-77_7c426e7f.bin
SCRIPTS := wakebreak.py identify.py selftest.py
TOOLS   := ipfw_images.py
TRACKED := $(SCRIPTS) $(TOOLS) Makefile README.md LICENSE requirements.txt $(INSTALLER_SRC) $(IPFW_SRC) \
           $(BLOBS) $(STOCKS) $(FIRMWARE)

SHACMD := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo 'shasum -a 256')

.PHONY: all rebuild verify selftest tarball clean toolchain
.SECONDARY:
.DELETE_ON_ERROR:

all: $(BLOBS)

# The blobs are tracked, so `make` alone has nothing to do in a fresh clone.
# This proves they still come out of the .S sources byte for byte.
rebuild:
	rm -rf $(BUILD) $(BLOBS)
	@$(MAKE) --no-print-directory all

toolchain:
	@command -v $(AS) >/dev/null || { \
	  echo "$(AS) not found. Install an arm-none-eabi toolchain (binutils 2.43.1"; \
	  echo "is known good) or set CROSS to its prefix, e.g."; \
	  echo "  make CROSS=/opt/devkitpro/devkitARM/bin/arm-none-eabi-"; \
	  exit 1; }

# Only install a freshly built blob if it is byte-identical to the pinned one:
# a toolchain that assembles differently must not silently reach a card.
define install_blob
	@size=$$(wc -c < $<); \
	if [ "$$size" -ne "$(SIZE_$(notdir $@))" ]; then \
	  echo "$< is $$size bytes, expected $(SIZE_$(notdir $@))."; exit 1; fi
	@got=$$($(SHACMD) < $< | cut -d' ' -f1); \
	if [ "$$got" != "$(SHA_$(notdir $@))" ]; then \
	  echo "$< sha256 $$got != pinned $(SHA_$(notdir $@))"; \
	  echo "Refusing to install. Rebuild with the documented toolchain, or"; \
	  echo "update the pin here only if you re-verify preimages on the card."; \
	  exit 1; fi
	@cp $< $@
	@echo "ok $@ ($(SIZE_$(notdir $@)) bytes, $(SHA_$(notdir $@)))"
endef

# One pair of rules per profile. A pattern rule cannot be used: profile a's
# blobs carry an empty suffix and % must match at least one character.
define profile_rules
$(BUILD)/installer$(call sfx,$(1)).bin: $(INSTALLER_SRC) | toolchain
	@mkdir -p $(BUILD)
	$(AS) $(ASFLAGS) $(IDEFS_$(1)) -o $(BUILD)/installer$(call sfx,$(1)).o $$<
	$(LD) -Ttext=$(IBASE_$(1)) -e $(INSTALLER_ENTRY) \
	      -o $(BUILD)/installer$(call sfx,$(1)).elf \
	         $(BUILD)/installer$(call sfx,$(1)).o
	$(OBJCOPY) -O binary -j .text $(BUILD)/installer$(call sfx,$(1)).elf $$@

# Zero-padded so the plant stays 46 dwords and the installer's `movs r2,#184`
# copy length is unchanged.
$(BUILD)/source_ipfw$(call sfx,$(1)).bin: $(IPFW_SRC) | toolchain
	@mkdir -p $(BUILD)
	$(AS) $(ASFLAGS) $(PDEFS_$(1)) -o $(BUILD)/source_ipfw$(call sfx,$(1)).o $$<
	$(LD) -Ttext=$(PBASE_$(1)) -e $(IPFW_ENTRY) \
	      -o $(BUILD)/source_ipfw$(call sfx,$(1)).elf \
	         $(BUILD)/source_ipfw$(call sfx,$(1)).o
	$(OBJCOPY) -O binary -j .text --pad-to=$(PPAD_$(1)) \
	      $(BUILD)/source_ipfw$(call sfx,$(1)).elf $$@

$(HOOK)/installer$(call sfx,$(1)).bin: $(BUILD)/installer$(call sfx,$(1)).bin
	$$(install_blob)

$(HOOK)/source_ipfw$(call sfx,$(1)).bin: $(BUILD)/source_ipfw$(call sfx,$(1)).bin
	$$(install_blob)
endef

$(foreach p,$(PROFILES),$(eval $(call profile_rules,$(p))))

define SUMS_BODY
$(foreach f,$(notdir $(BLOBS) $(STOCKS)),$(SHA_$(f))  $(HOOK)/$(f)
)$(SHA_asd_33-0-0-163_18debcc4.bin)  firmware/asd_33-0-0-163_18debcc4.bin
$(SHA_ta_22-0-0-77_7c426e7f.bin)  firmware/ta_22-0-0-77_7c426e7f.bin
endef
export SUMS_BODY

verify:
	@for f in $(SCRIPTS); do test -f $$f || { echo "MISSING $$f"; exit 1; }; done
	@printf '%s\n' "$$SUMS_BODY" | $(SHACMD) -c -
	@echo "all runtime artifacts present and pinned"

# No dependency on the build rules: the blobs ship, so verify/selftest and
# running the plant must work without a cross toolchain.
selftest:
	@$(PYTHON) selftest.py

tarball: verify selftest
	@rm -rf dist && mkdir -p dist/wake-and-break
	@tar cf - $(TRACKED) | (cd dist/wake-and-break && tar xf -)
	tar -C dist -czf dist/wake-and-break.tar.gz wake-and-break
	@echo "staged dist/wake-and-break.tar.gz"

clean:
	rm -rf $(BUILD) dist
