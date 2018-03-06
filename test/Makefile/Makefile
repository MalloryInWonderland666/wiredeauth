
include .config

CONFIG_FILE = .config
CONFIG_OPTS = `cat $(CONFIG_FILE) | grep '=y'`
CONFIG_DEFINES = $(patsubst %=y,-D%,$(CONFIG_OPTS))
#CONFIG_DEFINES = $(patsubst %=y,-D%,$(CONFIG_OPTS))

ifdef DEAUTH_METHOD_WLD
	CONFIG_DEFINES += GoFuckYourself
endif

target:
	@echo "${CONFIG_DEFINES}"
