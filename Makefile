AS ?= as
LD ?= ld

build/absurd: src/absurd.s
	@mkdir -p build
	$(AS) -o build/absurd.o $<
	$(LD) -static -nostdlib -z noexecstack --gc-sections -s -o $@ build/absurd.o

clean:
	rm -rf build

.PHONY: clean
