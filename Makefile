## Makefile for AVX2Patch

XCODE_ARGS = ARCHS=x86_64 ONLY_ACTIVE_ARCH=YES EXCLUDED_ARCHS=arm64

all:
	sudo rm -rf dist
	/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild $(XCODE_ARGS) -project AVX2Patch.xcodeproj -target AVX2Patch CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO
	mkdir -p dist
	sudo mv -f build/Release/AVX2Patch.kext dist/AVX2Patch.kext
	sudo chown -R 0:0 dist/AVX2Patch.kext

clean:
	sudo rm -rf dist
	sudo rm -rf build

load:
	sudo kextload dist/AVX2Patch.kext
unload:
	sudo kextunload dist/AVX2Patch.kext
reload:
	sudo kextunload dist/AVX2Patch.kext
	sudo kextload dist/AVX2Patch.kext

test:
	./test.sh

please_stop_kext_consent:
	sudo nvram 6C6F6769-6E67-0000-0000-000000000000:Disable=%01
	echo "Please restart the machine to take effect"
