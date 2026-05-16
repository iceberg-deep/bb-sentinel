TESTBED_PATH ?= ../bb-sentinel-testbed

.PHONY: integration-test
integration-test:
	@if [ ! -d "$(TESTBED_PATH)" ]; then \
		echo "testbed not found at $(TESTBED_PATH). Clone bb-sentinel-testbed beside this repo, or set TESTBED_PATH."; \
		exit 2; \
	fi
	BB_SENTINEL_PATH=$(CURDIR) python3 $(TESTBED_PATH)/tests/run_integration.py
