# Security Research on Kinibi

In this repository, you will find the tools that we have developed during our research to help us reverse engineer and also exploit Samsung's implementation of TrustZone, which is based on a Trusted OS called Kinibi.

## Bindings

In the `bindings/` folder, you will find Python bindings for the `libMcClient.so` library that is used to communicate with Trusted Applications and Secure Drivers. They were developed because we found it easier to write our exploits in Python, and they proved especially useful for the exercises given during our training sessions.

## Emulator

In the `emulator/` folder, you will find a Python script that makes use of the [Unicorn](https://www.unicorn-engine.org/) engine to emulate a trustlet. This tool was mainly used to test our exploits as it can print the instructions executed, register values and stack content.

## Fuzzer

In the `fuzzer/` folder, you will find a Python script that makes use of the [`afl-unicorn`](https://github.com/Battelle/afl-unicorn) project to fuzz trustlets. It is heavily based on the emulator. You will need to implement more tlApis/drApis if you intend to do some serious fuzzing.

## Scripts

In the `scripts/` folder, you will find various things:
- `mclf_loader`, a loader for trustlet binaries using the MCLF file format
- `tbase_loader`, a loader that extracts the various components of a SBOOT image
- `find_symbols`, a script that finds and renames the various tlApis/drApis stubs

The scripts are available both for IDA Pro and Ghidra, as we wanted our trainees to be able to use a free SRE.

## Tainting

In the `tainting/` folder, you will find a Python script that makes use of [Manticore](https://github.com/trailofbits/manticore) to find vulnerabilities in trustlets using symbolic execution. This was just an experiment, so the script is really basic.

## Contact

- Alexandre Adamski <<aadamski@quarkslab.com>>
- Joffrey Guilbon <<jguilbon@quarkslab.com>>
- Maxime Peterlin <<mpeterlin@quarslab.com>>
