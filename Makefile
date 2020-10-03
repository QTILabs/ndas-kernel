SRCS = $(wildcard xdp-*)
SRCS_CLEAN = $(addsuffix -clean,$(SRCS))

.PHONY: clean $(SRCS) $(SRCS_CLEAN)

all: $(SRCS)
clean: $(SRCS_CLEAN)

$(SRCS):
	$(MAKE) -C $@

$(SRCS_CLEAN):
	$(MAKE) -C $(subst -clean,,$@) clean
