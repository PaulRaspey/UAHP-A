Consolidated into github.com/PaulRaspey/uahp. Archived for history; tags remain browsable.

# UAHP-A: Actuation Handshake Protocol v1.1

**The physical bridge between digital cognition and the real world.**

UAHP handles trust. CSP handles thoughts. SMART-UAHP handles routing. **UAHP-A handles the translation from "agent decides" to "robot moves."**

This is where the chatbot becomes a robotics protocol.

## The Problem

An AI agent decides "move the arm to position X." That decision must be translated into specific G-code, ROS2 commands, GPIO signals, or API calls to physical actuators. The translation must be:

1. **Verified** — the agent is authorized to actuate
2. **Bounded** — the action is within safety limits
3. **Auditable** — every actuation produces a receipt
4. **Reversible** — where possible, actions can be undone

## Architecture

- **ActuationIntent** — the agent's desired physical action
- **ActuationPlan** — the translated command sequence
- **SafetyEnvelope** — physical limits the actuator must stay within (position, velocity, force, temperature)
- **ActuationReceipt** — signed proof of what happened in the physical world
- **ActuatorDriver** — pluggable interface to real hardware

## Lifecycle

```
Intent → Plan → Authorize → Execute → Receipt → Rollback
```

## v1.1: Safety-Graduated Trust

`ActuatorDescriptor` declares the actuator's safety class, which maps to a minimum required trust score:

| Safety Level | Min Trust | Example |
|:--|:--|:--|
| `PASSIVE` | 0.30 | read-only sensors |
| `LOW` | 0.50 | indicator LEDs |
| `MEDIUM` | 0.60 | motorized blinds |
| `HIGH` | 0.80 | industrial arms |
| `CRITICAL` | 0.95 + human sign-off | surgical, aerospace, energy |

Base gate: trust ≥ 0.4, POLIS standing ≥ 50.0.

## Supported Actuator Families

- **G-Code** — CNC, 3D printers, laser cutters (ships with `GCodeTranslator`, safe-Z-first motion planning)
- **ROS2** — Robot Operating System
- **GPIO** — Raspberry Pi, Arduino via serial
- **REST API** — smart home, industrial IoT
- **Modbus** — industrial automation

`SimulationDriver` ships for dev/test; implement `ActuatorDriver` for real hardware.

## Integration Points

- **UAHP** — identity verification before any actuation
- **POLIS** — standing check (agent must be licensed for physical actions)
- **CDF** — actuation intents are scanned before execution
- **UAM** — actuation results are stored as procedural memories

## Design Philosophy

The same handshake that proves *"I am who I say I am"* (UAHP) now extends to *"I did what I said I would do"* (UAHP-A).

## Running Tests

```bash
python3 test_integration.py
```

## Part of the UAHP Stack

UAHP-A is Layer 6 of the UAHP agentic stack. See [UAHP-Stack](https://github.com/PaulRaspey/UAHP-Stack) for the full architecture.

## Author

Paul Raspey | MIT License
