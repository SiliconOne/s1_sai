# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco").
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# END_LEGAL

include $(MakefileTemplateRoot)/Makefile.module_pre

ifeq ($(ENABLE_SERIALIZATION), 1)
sai-prereqs := | api-include $(cereal-gen-as-dependency) $(cereal-configured)
CFLAGS += -DENABLE_SERIALIZATION=1
else
sai-prereqs := | api-include $(cereal-gen-as-dependency)
endif

sai-includes := -I$(SDK_OUTPUT_DIR)/include -I$(INCLUDE_OUTPUT_DIR) -Isrc/ -I$(INCLUDE_OUTPUT_DIR)/sai -I../externals/jansson $(PYTHON_INC_FLAGS) -I$(cereal-include-path) -I$(LIBNL3_INC_DIR)
sai-link-libs = -ldl -L$(SDK_OUTPUT_DIR)/lib -lhld -lapi_serial -L$(LIBNL3_LINK_DIR) -lnl-genl-3 -lnl-3
CFLAGS += -DSAI_VERSION=$(sai-ver) -DCURRENT_SAI_VERSION_CODE=$(SAI_VER_CODE)
CXXFLAGS += -DSAI_VERSION=$(sai-ver) -DCURRENT_SAI_VERSION_CODE=$(SAI_VER_CODE)

PKG := sai
PKG-TARGETS := libs swiglib
PKG-PATH := src

api-sai-auto-gen-attr-file := $(BASE_OUTPUT_DIR)/build/src/auto_gen_attr.h
api-sai-auto-tostrings-file := $(BASE_OUTPUT_DIR)/build/src/auto_tostrings.cpp

ifeq ($(SDK_BIN), 1)
sdk-out-configured = $(SDK_OUTPUT_DIR)/.sdk-out-configured
$(sdk-out-configured):
	mkdir -p $(@D)
	ln -s $(SDK_ROOT)/driver/include $(SDK_OUTPUT_DIR)
	ln -s $(SDK_ROOT)/driver//bin $(SDK_OUTPUT_DIR)
	ln -s $(SDK_ROOT)/driver/lib $(SDK_OUTPUT_DIR)
	ln -s $(SDK_ROOT)/driver/lib_static $(SDK_OUTPUT_DIR)
	ln -s $(SDK_ROOT)/driver/pylib $(SDK_OUTPUT_DIR)
	ln -s $(SDK_ROOT)/driver/res $(SDK_OUTPUT_DIR)
	ln -s $(SDK_ROOT)/driver/modules $(SDK_OUTPUT_DIR)
	touch $@
endif

PKG-COMPILE-PREREQS := $(sai-prereqs) $(api-sai-auto-gen-attr-file)
ifeq ($(SDK_BIN), 1)
PKG-COMPILE-PREREQS += $(sdk-out-configured)
endif
PKG-INCLUDE-FLAGS := $(sai-includes)
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) $(sai-link-libs)

PKG-GENERATED-H-FILES := auto_gen_attr.h
PKG-GENERATED-CPP-FILES := auto_tostrings.cpp

PKG-SWIG-COMPILE-PREREQS := $(sai-prereqs)
PKG-SWIG-INCLUDE-FLAGS := $(sai-includes) -DCURRENT_SAI_VERSION_CODE=$(SAI_VER_CODE)
PKG-SWIG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) $(sai-link-libs)

PKG-CEREAL-NUM-OF-GENERATED-FILES := 32
PKG-CEREAL-GEN := True
PKG-CEREAL-CONFIG-FILE := serialize_config.cfg

include $(MakefileTemplateRoot)/Makefile.module_vars
$(PKG)-cereal-module-dirs += $(INCLUDE_OUTPUT_DIR)/sai/
include $(MakefileTemplateRoot)/Makefile.module_targets

$(api-sai-auto-gen-attr-file): src/auto_gen_attr.h_$(SAI_VER_SUFFIX)
	@$(MKDIR) -p $(BASE_OUTPUT_DIR)/build/src
	@echo copying SAI auto_gen_attr.h version $(SAI_VER_SUFFIX) $(SAI_VER_CODE)
	@$(CP) $^ $@

$(api-sai-auto-tostrings-file): src/auto_tostrings.cpp_$(SAI_VER_SUFFIX)
	@$(MKDIR) -p $(BASE_OUTPUT_DIR)/build/src
	@echo copying SAI auto_tostrings.cpp version $(SAI_VER_SUFFIX) $(SAI_VER_CODE)
	@$(CP) $^ $@
