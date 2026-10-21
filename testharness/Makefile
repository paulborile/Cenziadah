# Test harness: a deliberately-vulnerable victim + a real exploit, used ONLY to
# validate cenziadah against a genuine compromise. Built separately from the
# detector and never linked into it.
#
# The victim is built -no-pie with an executable stack and no stack protector, and
# is launched under `setarch -R` by the scenarios, so a classic stack buffer
# overflow deterministically lands and runs shellcode. These are the conditions of
# an exploitable target, intentionally chosen for a reproducible test; they are NOT
# production-safe settings.

CC      ?= cc
CFLAGS  ?= -O0 -g -fno-stack-protector -no-pie
VICTIM  := victim/victim
EXPLOIT := exploit/exploit

.PHONY: build scenarios clean

build: $(VICTIM) $(EXPLOIT) ## build the vulnerable victim and the exploit

$(VICTIM): victim/victim.c
	$(CC) $(CFLAGS) -o $@ $<

$(EXPLOIT): exploit/main.go
	cd .. && go build -o testharness/exploit/exploit ./testharness/exploit/

scenarios: build ## run the compromise integration test
	cd .. && go test -tags harness -count=1 ./testharness/scenarios/

clean:
	rm -f $(VICTIM) $(EXPLOIT)
