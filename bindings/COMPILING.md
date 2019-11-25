# Capstone/Keystone for Android

Here are the commands we have used to compile Capstone/Keystone.

## Compiling

### Capstone

```
git clone https://github.com/aquynh/capstone capstone && cd capstone
mkdir build64 && cd build64
cmake -DCMAKE_SYSTEM_NAME=Android -DCMAKE_ANDROID_NDK=/path/to/android-ndk -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a -DCMAKE_BUILD_TYPE=Release -G"Unix Makefiles" ..
make -j8
```

### Keystone

```
git clone https://github.com/keystone-engine keystone && cd keystone
mkdir build64 && cd build64
cmake -DCMAKE_SYSTEM_NAME=Android -DCMAKE_ANDROID_NDK=/path/to/android-ndk -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -G"Unix Makefiles" ..
make -j8
```

## Installing

Here are the commands we have used to install Capstone/Keystone.

### Capstone

```
adb push capstone /data/local/tmp
adb shell
$ . /data/local/tmp/python3/tools/env.sh
$ cd /data/local/tmp/capstone/bindings/python
$ cp ../../build64/libcapstone.* prebuilt
$ python3.7 setup.py install
$ cd /data/local/tmp && rm -rf capstone
```

### Keystone

```
adb push keystone /data/local/tmp
adb shell
$ . /data/local/tmppython3/tools/env.sh
$ cd /data/local/tmp/keystone/bindings/python
$ cp ../../build64/llvm/lib/libkeystone.so /data/local/tmp/python3/usr/lib
$ python3.7 setup.py install
$ cd /data/local/tmp && rm -rf keystone
```
