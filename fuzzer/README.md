# Fuzzer

This fuzzer is based on the [`afl-unicorn`](https://github.com/Battelle/afl-unicorn) project. We have only made some slight changes to the emulator code: executing one instruction to start the forkserver, loading the input file and forcing a crash on errors.

You will need to implement more tlApis/drApis if you intend to do some serious fuzzing, as we couldn't release ours.

## Installation

Follow the instructions in [this blog-post](https://medium.com/hackernoon/afl-unicorn-fuzzing-arbitrary-binary-code-563ca28936bf) to get afl-unicorn up and running.
