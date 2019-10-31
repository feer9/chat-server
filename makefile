# If the first argument is "run"...
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

.PHONY: all
all: build

.PHONY: build
build: server


server: server-main.c server.h 
	gcc -Wall -no-pie server-main.c -o server -lpthread

.PHONY: run
run: server
	./server $(RUN_ARGS)

clean:
	rm -rf server