# 2026-Team-1-Deep-Point
# DeepPoint — Secure Depth Camera Data Pipeline

A brief one-line description of your IOT project.

> Encrypting depth-camera point-cloud data on IoT edge devices using RSA and AES-128-GCM, with side-by-side performance benchmarking.

## Table of Contents

- [Overview](#overview)
- [Hardware Components](#hardware-components)
- [Software and Dependencies](#software-and-dependencies)
- [Usage](#usage)
- [Results and Demonstration](#results-and-demonstration)

## Overview

DeepPoint addresses the problem of **securing sensor data captured from depth cameras** before transmitting it from constrained IoT edge devices to a backend server. Depth data (point clouds, depth maps) can leak sensitive information about people and physical spaces, so it must be protected in transit and at rest.

This repository contains two proof-of-concept encryption pipelines applied to the same depth-camera dataset (`depth-selected.zip`), allowing direct comparison of:

- **RSA** (asymmetric, custom number-theory implementation built on Miller–Rabin primality, modular inverse, and modular exponentiation) — see [RSA_Encrypt.py](RSA_Encrypt.py) and [Number_Package.py](Number_Package.py).
- **AES-128-GCM** (symmetric, authenticated encryption via the audited `cryptography` library) — see [encrypt_aes.py](encrypt_aes.py).

Main features:

- End-to-end encrypt → decrypt → integrity-check round trip for a real depth-camera dataset.
- Block-wise RSA encryption sized to the modulus bit length.
- Authenticated AES-GCM encryption with a 96-bit IV per NIST SP 800-38D.
- Per-stage timing (key generation, encryption, decryption) and throughput reporting for direct algorithm comparison.

## Hardware Components

List all the components used in your project:

- **Intel RealSense Depth Camera** (or equivalent stereo / ToF depth sensor) — captures the raw depth frames packaged in `depth-selected.zip`.
- **Edge compute device** — e.g., Raspberry Pi 4 / NVIDIA Jetson Nano — runs the encryption pipeline before transmission.
- **Host workstation** — used for key generation, decryption, and benchmarking.
- **USB 3.0 cable** — connects the depth camera to the edge device.
- **Network link (Wi-Fi / Ethernet)** — transports encrypted JSON payloads between edge and host.

## Software and Dependencies

Mention the programming language and libraries used:

- **Language:** Python 3.9+
- **Libraries:**
  - [`cryptography`](https://cryptography.io/) — provides the audited AES-128-GCM primitive used in [encrypt_aes.py](encrypt_aes.py).
  - `numpy` — used inside the modular-inverse routine in [Number_Package.py](Number_Package.py).
  - Standard library: `json`, `pathlib`, `os`, `time`, `random`, `math`.

Install dependencies:

```bash
pip install cryptography numpy
```

## Usage

1. Place the depth-camera dataset (`depth-selected.zip`) somewhere accessible and update the `zip_file` path at the bottom of each script.
2. Run the RSA pipeline:

   ```bash
   python RSA_Encrypt.py
   ```

   Produces `depth-selected_encrypted.json` and `depth-selected_recovered.zip`.

3. Run the AES-128-GCM pipeline:

   ```bash
   python encrypt_aes.py
   ```

   Produces `depth-selected_encrypted_aes.json` and `depth-selected_recovered_aes.zip`.

4. Each script prints key-generation, encryption, and decryption timings, encryption throughput, and a round-trip integrity check (`Round-trip match: True`).

## Results and Demonstration

Both pipelines successfully round-trip the depth dataset (`Round-trip match: True`). The benchmark output highlights the practical contrast between the two schemes:

- **RSA** — slow, block-by-block, no built-in integrity, suitable only for small payloads or key exchange.
- **AES-128-GCM** — orders of magnitude faster, native support for arbitrary-length data, and provides authenticated integrity via the GMAC tag.

Run either script to reproduce the timing table and verify the recovered `.zip` matches the original byte-for-byte.
Collapse


----------------------------------------------------------------------------------------------------------------------------------------------------------------------

To run with the ML model, we utilized RadarHD, which we have included in an acknowledement/citation here:
@INPROCEEDINGS{10161429,
author={Prabhakara, Akarsh and Jin, Tao and Das, Arnav and Bhatt, Gantavya and Kumari, Lilly and Soltanaghai, Elahe and Bilmes, Jeff and Kumar, Swarun and Rowe, Anthony},
booktitle={2023 IEEE International Conference on Robotics and Automation (ICRA)}, 
title={High Resolution Point Clouds from mmWave Radar}, 
year={2023},
volume={},
number={},
pages={4135-4142},
doi={10.1109/ICRA48891.2023.10161429}}

Link to github: https://github.com/akarsh-prabhakara/RadarHD 








