# Introduction

EEMBC® SecureMark™ is an objective, standardized benchmarking framework for measuring the efficiency of cryptographic processing solutions. Within SecureMark, EEMBC plans to support test and analysis of various security profiles for different application domains. The first version is called SecureMark-TLS, which focuses on Transport Layer Security (TLS) for internet of things (IoT) edge nodes.

This repository contains the SecureMark-TLS firmware for *standalone* execution, which does not require the external hardware test-harness, nor the host GUI software. This means you can run the benchmark and collect just performance scores. In order collect official energy scores and upload them to the EEMBC website, you will need both the hardware for the test-harness and a license for the host software. While this is still the same benchmark workload, the host software is needed to determines the run was valid (i.e. to discourage cheating and verify adherence to the "Run Rules"), and the test-harness is needed to collect the measurements required to compute the energy-efficiency score.

# Firmware

The firmware is divided into two sections: the `monitor` and the `profile`. The `monitor` contains a basic API to the device under test (DUT), and the `profile` contains the actual benchmark code and algorithm API. In the code, files and functions that start with `ee_` cannot be changed, whereas those which begin with `th_` in most cases must be edited, as they are empty hardware-specific implementation layers.

## Monitor

The monitor provides a basic set of platform requirements to communicate with the device under test (DUT). This includes a UART interface, a 1-ms timer, and a GPIO used for external triggering. The selfhosted example uses console I/O and a system timer to take the place of the hardware requirements.

## Profile

The profile contains the components from which the final benchmark score is comprised. By calling these components with different configurations, the SecureMark-TLS benchmark emulates a TLS handshake and data transfer using the following cryptoprimitives:

* Ephemeral ECDH key exchange (deterministic),
* ECDSA with a SHA256 HMAC,
* SHA256 hashing, and
* both AES 128 CCM and ECB exchanges 

These primitives were selected because they resemble what is most popular in the constrained IoT space at this time.

In order to analyze energy efficiency, the API provides a thin layer to each primitive which can be implemented with software -or- hardware. This allows enormous flexibility: the same platform can be tested with and without hardware acceleration by a few changes to the underlying implementation layer.

A TLS handshake with this configuration has 14 steps and generates over a dozen different contexts with various-sized payloads. The firmware API allows the host software to configure and execute these primitives with different input data sizes in order to both emulate the handshake for an official score, and to provide exploration and analysis outside the scope of the benchmark. (The host GUI provides additional dynamic configuration options than the self-hosted code.)

The high-level wrapper for each primitive is implemented in the `profile/ee_*` files. The `profiles/th_api/th_*` files provide the user implementation. In the `examples` folder, the self-hosted code implements the `th_*` functionality with Arm's mbedTLS(tm) library. A version of mbedTLS has been provided for completeness, but this is just one possible implementation. A developer could use wolfSSL or LibTomCrypt, or the hardware acceleration libraries found on many Arm-based MCU and SoC products. The EEMBC API makes porting quick and easy.

The 14 subphases in the test consist of:

| Phase | Description                |
|-------|----------------------------|
| 1     | AES128 ECB Encrypt [144B]  |
| 2     | AES128 ECB Encrypt [224B]  |
| 3     | AES128 ECB Encrypt [320B]  |
| 4     | AES128 CCM Encrypt [52B]   |
| 5     | AES128 CCM Decrypt [168B]  |
| 6     | ECDH p256r1 Secret Mix     |
| 7     | ECDSA p256r1 Sign          |
| 8     | ECDSA p256r1 Verify        |
| 9     | SHA256 [23B]               |
| 10    | SHA256 [57B]               |
| 11    | SHA256 [384B]              |
| 12    | SHA256+AES Multi Mix       |
| 13    | SHA256 [4224B]             |
| 14    | Data Tx (AES ENC) [2KB]    |  

## Scoring

By design, the profile firmware only contains the primitives for the test, and not the actual test sequence itself. Normally this is controlled by the host software, which also provides additional analysis capabilities. However, in this repository, the self-hosted version invokes each primitive with the correct number of iterations, and summarizes the performance results according on its own.

The *performance* score of the benchmark is the sum of the weighted runtimes, inverted (so that decreasing time indicates increasing score), and then multiplied by 1000 to scale into an integer range.

Similarly, the *energy* score is the sum of the weighted Joule consumption.

The weighted values were determined by vote in the SecureMark working group. 

## Examples

See the README in the `examples` folder for information on building the self-hosted benchmark.

# Full Version

To obtain the host GUI, user manual, and bill-of-materials for the EEMBC IoTConnect test-harness framework, please contact [support@eembc.org](mailto:support@eembc.org).

# Licensing

This software is provided under an extended Apache-2.0 license. The extension includes an "Acceptable Use Agreement", which in the shortest possible terms prevents someone from changing the code and calling it SecureMark, which would diminish EEMBC's efforts at standardization. Please review the attached license before you begin. A corporate license is required to publish scores in documents such as marketing and PR documents, and to obtain support. Please contact support@eembc.org for information on corporate licensing.

# About EEMBC

Founded in 1997, EEMBC is US non-profit which develops  benchmarks for the hardware and software used in autonomous driving, mobile imaging, the Internet of Things, mobile devices, and many other applications. The EEMBC community includes member companies, commercial licensees, and academic licensees at institutions of higher learning around the world. Visit our [website](https://www.eembc.org).
