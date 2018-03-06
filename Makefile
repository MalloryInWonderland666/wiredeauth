
compile:
	$(MAKE) -C wiredeauth/
documentation:
	$(MAKE) -C doc/
all:
	$(MAKE) -C wiredeauth/
	$(MAKE) -C doc/
clean:
	$(MAKE) -C wiredeauth/ clean
	$(MAKE) -C doc/ clean
