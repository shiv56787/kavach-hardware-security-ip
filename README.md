# kavach-hardware-security-ip
KAVACH is a hardware-level autonomous security IP for detecting and responding to physical and fault-injection attacks on SoCs.

Unlike software-based security solutions, KAVACH operates entirely at the hardware level, enabling real-time detection, classification, response, and recovery even when software or firmware is compromised.

---

## Problem Statement
Modern SoCs are vulnerable to physical attacks such as power glitching, clock manipulation, thermal attacks, and control-flow fault injection.  
Software-based security mechanisms are slow, bypassable, and ineffective against such attacks.

---

## Solution
KAVACH IP introduces a hardware-first security layer that continuously monitors multiple attack surfaces and autonomously reacts to threats in real time.  
The system performs detection, threat classification, response execution, forensic logging, and controlled recovery without any software intervention.

---

## Key Features
- Fully hardware-based security (no firmware dependency)
- Real-time multi-domain anomaly detection
- Adaptive baseline learning using EWMA
- Autonomous threat classification
- Graded hardware response and isolation
- Secure forensic logging
- Controlled system recovery

---

## Architecture Overview
KAVACH IP consists of the following hardware modules:

1. Power Monitor  
2. Timing Monitor  
3. Temperature Monitor  
4. Execution Monitor  
5. EWMA Baseline Engine  
6. Threat Classifier FSM  
7. Response Controller  
8. Forensic Capture Unit  
9. Recovery State Machine  

---

## Threat Levels
- NONE – Normal operation  
- LOW – Suspicious behavior  
- MEDIUM – Confirmed anomaly  
- HIGH – Active attack detected  
- CRITICAL – Coordinated or physical attack  

---

## Hardware Responses
Depending on the threat level, KAVACH IP can:
- Trigger alerts
- Throttle clocks
- Isolate buses and peripherals
- Disable debug access
- Zeroize sensitive data
- Enter full system lockdown
- Perform controlled recovery

---

## Implementation Status
- Fully synthesizable Verilog RTL
- End-to-end simulation completed
- FPGA implementation targeted on Artix-7 (Nexys A7)

---

## Applications
- Automotive ECUs
- Secure SoCs
- Defense and aerospace systems
- Safety-critical embedded platforms

---

## Competition Context
This project is submitted as part of the AMD Slingshot competition to demonstrate innovative, hardware-first security for next-generation computing systems.
