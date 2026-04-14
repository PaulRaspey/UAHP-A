"""
UAHP-A: Actuation Handshake Protocol v1.1
============================================
The physical bridge between digital cognition and the real world.

UAHP handles trust. CSP handles thoughts. SMART-UAHP handles routing.
UAHP-A handles the translation from "agent decides" to "robot moves."

This is where the chatbot becomes a robotics protocol.

v1.1 additions:
  - ActuatorDescriptor: declarative actuator registration with safety-level
    graduated trust requirements (merged from parallel build)
  - Safety level to minimum trust mapping:
    PASSIVE=0.3, LOW=0.5, MEDIUM=0.6, HIGH=0.8, CRITICAL=0.95+human

The problem UAHP-A solves:
  An AI agent decides "move the arm to position X." That decision
  must be translated into specific G-code, ROS2 commands, GPIO signals,
  or API calls to physical actuators. The translation must be:
    1. Verified (the agent is authorized to actuate)
    2. Bounded (the action is within safety limits)
    3. Auditable (every actuation produces a receipt)
    4. Reversible (where possible, actions can be undone)

Architecture:
  - ActuationIntent: the agent's desired physical action
  - ActuationPlan: the translated command sequence
  - SafetyEnvelope: physical limits the actuator must stay within
  - ActuationReceipt: signed proof of what happened in the physical world
  - ActuatorDriver: pluggable interface to real hardware

Integration points:
  - UAHP: identity verification before any actuation
  - POLIS: standing check (agent must be licensed for physical actions)
  - CDF: actuation intents are scanned before execution
  - UAM: actuation results are stored as procedural memories

Supported actuator families (via drivers):
  - G-Code (CNC, 3D printers, laser cutters)
  - ROS2 (Robot Operating System)
  - GPIO (Raspberry Pi, Arduino via serial)
  - REST API (smart home, industrial IoT)
  - Modbus (industrial automation)

Design philosophy: the same handshake that proves "I am who I say I am"
(UAHP) now extends to "I did what I said I would do" (UAHP-A).

Author: Paul Raspey
License: MIT
"""

import hashlib
import json
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


# ── Actuation Types ───────────────────────────────────────────────────────────

class ActuatorFamily(str, Enum):
    """Families of physical actuators."""
    GCODE = "gcode"               # CNC, 3D printing, laser
    ROS2 = "ros2"                 # Robot Operating System
    GPIO = "gpio"                 # Direct pin control
    REST_API = "rest_api"         # HTTP-controlled devices
    MODBUS = "modbus"             # Industrial protocol
    SERIAL = "serial"             # Raw serial commands
    SIMULATION = "simulation"     # Virtual actuator for testing


class ActuationStatus(str, Enum):
    """Lifecycle states of an actuation request."""
    PENDING = "pending"           # Intent received, not yet planned
    PLANNED = "planned"           # Plan generated, awaiting authorization
    AUTHORIZED = "authorized"     # UAHP + POLIS checks passed
    EXECUTING = "executing"       # Commands being sent to actuator
    COMPLETED = "completed"       # All commands executed successfully
    FAILED = "failed"             # Execution failed
    ABORTED = "aborted"           # Manually or safety-stopped
    ROLLED_BACK = "rolled_back"   # Reversal completed


class SafetyLevel(str, Enum):
    """Safety classification for actuation requests."""
    SAFE = "safe"                 # Within all limits, no review needed
    CAUTION = "caution"           # Near limits, proceed with monitoring
    RESTRICTED = "restricted"     # Requires human confirmation
    PROHIBITED = "prohibited"     # Outside safety envelope, rejected


# ── v1.1: Actuator Descriptor (merged from parallel build) ──────────────────

class ActuatorSafetyClass(str, Enum):
    """
    How dangerous is this actuator if misused?
    Maps to minimum UAHP trust score required to command it.

    v1.1 addition.
    """
    PASSIVE = "passive"           # Display, speaker, LED. No physical risk.
    LOW = "low"                   # Small servo, GPIO toggle. Minor pinch risk.
    MEDIUM = "medium"             # Robot arm, stepper. Collision risk.
    HIGH = "high"                 # CNC, industrial motor. Injury risk.
    CRITICAL = "critical"         # Drone rotor, heavy machinery. Life risk.


# Safety class -> minimum UAHP trust score
SAFETY_TRUST_REQUIREMENTS = {
    ActuatorSafetyClass.PASSIVE: 0.3,
    ActuatorSafetyClass.LOW: 0.5,
    ActuatorSafetyClass.MEDIUM: 0.6,
    ActuatorSafetyClass.HIGH: 0.8,
    ActuatorSafetyClass.CRITICAL: 0.95,
}


@dataclass
class ActuatorDescriptor:
    """
    Describes a physical actuator's capabilities and constraints.

    This is what an actuator advertises to the UAHP-Registry so agents
    can discover what physical actions are available. The safety_class
    determines the minimum trust score required to command it.

    v1.1 addition: merged from parallel build.
    """
    actuator_id: str = ""
    name: str = ""
    actuator_family: str = ActuatorFamily.SIMULATION.value
    safety_class: str = ActuatorSafetyClass.LOW.value

    # Physical constraints
    min_value: float = 0.0
    max_value: float = 180.0
    units: str = "degrees"
    resolution: float = 1.0
    max_velocity: float = 0.0
    max_force_newtons: float = 0.0

    # UAHP integration
    owner_agent_uid: str = ""
    requires_human_confirm: bool = False
    physical_location: str = ""

    @property
    def min_trust_score(self) -> float:
        """Minimum UAHP trust score to command this actuator."""
        return SAFETY_TRUST_REQUIREMENTS.get(
            ActuatorSafetyClass(self.safety_class),
            0.5,
        )

    def to_registry_entry(self) -> Dict:
        """Format for UAHP-Registry advertisement."""
        return {
            "type": "actuator",
            "id": self.actuator_id,
            "name": self.name,
            "family": self.actuator_family,
            "safety_class": self.safety_class,
            "min_trust": self.min_trust_score,
            "constraints": {
                "range": [self.min_value, self.max_value],
                "units": self.units,
                "resolution": self.resolution,
            },
            "human_confirm": self.requires_human_confirm,
        }


# ── Core Data Structures ─────────────────────────────────────────────────────

@dataclass
class SafetyEnvelope:
    """
    Physical safety limits for an actuator.

    Defines the bounding box within which the actuator is allowed
    to operate. Any command that would move outside this envelope
    is rejected before reaching the hardware.

    Think of it as a geofence, but for physical motion.
    """
    # Positional limits (mm for linear, degrees for rotary)
    x_min: float = -1000.0
    x_max: float = 1000.0
    y_min: float = -1000.0
    y_max: float = 1000.0
    z_min: float = 0.0
    z_max: float = 500.0

    # Speed limits
    max_velocity_mm_s: float = 100.0
    max_acceleration_mm_s2: float = 500.0

    # Force/torque limits
    max_force_n: float = 50.0
    max_torque_nm: float = 10.0

    # Temperature limits (for heated actuators)
    max_temp_c: float = 250.0

    # Power limits
    max_power_w: float = 500.0

    # Operational limits
    max_continuous_runtime_s: float = 3600.0
    emergency_stop_enabled: bool = True

    def check_position(self, x: float, y: float, z: float) -> SafetyLevel:
        """Check if a position is within the safety envelope."""
        margin = 0.1  # 10% margin for caution zone

        if not (self.x_min <= x <= self.x_max and
                self.y_min <= y <= self.y_max and
                self.z_min <= z <= self.z_max):
            return SafetyLevel.PROHIBITED

        # Check if we're near the edges
        x_range = self.x_max - self.x_min
        y_range = self.y_max - self.y_min
        z_range = self.z_max - self.z_min

        near_edge = (
            (x - self.x_min < x_range * margin) or
            (self.x_max - x < x_range * margin) or
            (y - self.y_min < y_range * margin) or
            (self.y_max - y < y_range * margin) or
            (z - self.z_min < z_range * margin) or
            (self.z_max - z < z_range * margin)
        )

        return SafetyLevel.CAUTION if near_edge else SafetyLevel.SAFE

    def check_velocity(self, velocity_mm_s: float) -> SafetyLevel:
        if velocity_mm_s > self.max_velocity_mm_s:
            return SafetyLevel.PROHIBITED
        elif velocity_mm_s > self.max_velocity_mm_s * 0.9:
            return SafetyLevel.CAUTION
        return SafetyLevel.SAFE


@dataclass
class ActuationIntent:
    """
    What the agent wants to do in the physical world.

    This is the high-level description before translation to
    machine commands. The intent is human-readable and auditable.
    """
    intent_id: str
    agent_uid: str
    timestamp: float
    description: str              # Human-readable: "move arm to pick position"
    target_actuator: str          # Actuator identifier
    actuator_family: str          # ActuatorFamily value
    parameters: Dict[str, Any]    # Family-specific parameters
    priority: int = 5             # 1 (highest) to 10 (lowest)
    timeout_s: float = 30.0
    reversible: bool = True
    requires_confirmation: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ActuationCommand:
    """
    A single translated machine command.

    The atomic unit of physical action. An ActuationPlan contains
    a sequence of these commands.
    """
    command_id: str
    command_type: str             # "gcode", "ros2_action", "gpio_write", etc.
    raw_command: str              # The actual command string/bytes
    expected_duration_ms: float
    safety_level: str             # SafetyLevel value
    reversible: bool
    reverse_command: Optional[str] = None  # Command to undo this action
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActuationPlan:
    """
    A complete translated action plan.

    Contains the sequence of machine commands, safety checks,
    and the estimated physical outcome.
    """
    plan_id: str
    intent_id: str
    agent_uid: str
    created_at: float
    commands: List[ActuationCommand]
    overall_safety: str           # Worst safety level in the command sequence
    estimated_duration_ms: float
    estimated_energy_j: float
    reversible: bool
    status: str = ActuationStatus.PLANNED
    authorization_signature: Optional[str] = None

    @property
    def command_count(self) -> int:
        return len(self.commands)


@dataclass
class ActuationReceipt:
    """
    Signed proof of what happened in the physical world.

    This is the UAHP-A equivalent of a CompletionReceipt.
    It records the intent, the plan, what actually executed,
    sensor readings during execution, and the outcome.

    The receipt is signed with the agent's UAHP key, creating
    a tamper-evident record of physical actions.
    """
    receipt_id: str
    intent_id: str
    plan_id: str
    agent_uid: str
    target_actuator: str
    timestamp_start: float
    timestamp_end: float
    status: str                   # ActuationStatus
    commands_executed: int
    commands_total: int
    sensor_readings: Dict[str, Any]
    errors: List[str]
    energy_consumed_j: float
    signature: str                # UAHP signature over the receipt
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.status == ActuationStatus.COMPLETED

    @property
    def duration_ms(self) -> float:
        return (self.timestamp_end - self.timestamp_start) * 1000

    def to_dict(self) -> Dict:
        return asdict(self)


# ── Actuator Driver Interface ─────────────────────────────────────────────────

class ActuatorDriver(ABC):
    """
    Abstract interface for physical actuator control.

    Implement this for each actuator family. The driver handles
    the translation from ActuationCommands to hardware-specific
    protocols.

    Shipped drivers: SimulationDriver (for testing).
    Community drivers: GCodeDriver, ROS2Driver, GPIODriver, etc.
    """

    family: ActuatorFamily = ActuatorFamily.SIMULATION

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the actuator. Returns True on success."""
        ...

    @abstractmethod
    def execute(self, command: ActuationCommand) -> Tuple[bool, Dict[str, Any]]:
        """
        Execute a single command.
        Returns (success, sensor_readings).
        """
        ...

    @abstractmethod
    def emergency_stop(self) -> bool:
        """Immediately halt all actuator motion."""
        ...

    @abstractmethod
    def read_sensors(self) -> Dict[str, Any]:
        """Read current sensor state from the actuator."""
        ...

    @abstractmethod
    def disconnect(self) -> bool:
        """Clean shutdown of actuator connection."""
        ...

    def is_connected(self) -> bool:
        """Check if the actuator is currently connected."""
        return False


class SimulationDriver(ActuatorDriver):
    """
    Virtual actuator for testing and development.

    Simulates physical actions with realistic timing.
    No actual hardware required. Logs all commands.
    """

    family = ActuatorFamily.SIMULATION

    def __init__(self, name: str = "sim_actuator_01"):
        self.name = name
        self._connected = False
        self._position = {"x": 0.0, "y": 0.0, "z": 0.0}
        self._command_log: List[Dict] = []
        self._error_rate = 0.0    # Set > 0 to simulate failures

    def connect(self) -> bool:
        self._connected = True
        return True

    def execute(self, command: ActuationCommand) -> Tuple[bool, Dict[str, Any]]:
        if not self._connected:
            return False, {"error": "not connected"}

        # Simulate execution time
        import random
        if random.random() < self._error_rate:
            return False, {"error": "simulated actuator fault"}

        # Parse position commands
        if "position" in command.parameters:
            pos = command.parameters["position"]
            self._position.update(pos)

        self._command_log.append({
            "command_id": command.command_id,
            "raw": command.raw_command,
            "timestamp": time.time(),
        })

        return True, {
            "position": dict(self._position),
            "temperature_c": 22.0,
            "force_n": 0.0,
        }

    def emergency_stop(self) -> bool:
        self._command_log.append({
            "command_id": "E_STOP",
            "raw": "EMERGENCY_STOP",
            "timestamp": time.time(),
        })
        return True

    def read_sensors(self) -> Dict[str, Any]:
        return {
            "position": dict(self._position),
            "temperature_c": 22.0,
            "force_n": 0.0,
            "connected": self._connected,
        }

    def disconnect(self) -> bool:
        self._connected = False
        return True

    def is_connected(self) -> bool:
        return self._connected


class GCodeTranslator:
    """
    Translate ActuationIntents into G-code command sequences.

    Supports:
    - Linear moves (G0/G1)
    - Arc moves (G2/G3)
    - Homing (G28)
    - Tool changes
    - Temperature control (M104/M140)
    """

    @staticmethod
    def translate(intent: ActuationIntent, envelope: SafetyEnvelope) -> List[ActuationCommand]:
        """Translate an intent into G-code commands."""
        commands = []
        params = intent.parameters

        action = params.get("action", "move")

        if action == "move":
            x = params.get("x", 0.0)
            y = params.get("y", 0.0)
            z = params.get("z", 0.0)
            feedrate = params.get("feedrate", envelope.max_velocity_mm_s * 60 * 0.5)

            # Safety check
            safety = envelope.check_position(x, y, z)
            if safety == SafetyLevel.PROHIBITED:
                return []  # Refuse to generate commands outside envelope

            # Move to safe Z first, then XY, then target Z
            commands.append(ActuationCommand(
                command_id=f"cmd-{uuid.uuid4().hex[:8]}",
                command_type="gcode",
                raw_command=f"G0 Z{envelope.z_max * 0.9:.2f} F{feedrate:.0f}",
                expected_duration_ms=500,
                safety_level=SafetyLevel.SAFE,
                reversible=True,
                reverse_command=f"G0 Z{z:.2f}",
                parameters={"z": envelope.z_max * 0.9},
            ))
            commands.append(ActuationCommand(
                command_id=f"cmd-{uuid.uuid4().hex[:8]}",
                command_type="gcode",
                raw_command=f"G0 X{x:.2f} Y{y:.2f} F{feedrate:.0f}",
                expected_duration_ms=1000,
                safety_level=safety,
                reversible=True,
                parameters={"x": x, "y": y, "position": {"x": x, "y": y}},
            ))
            commands.append(ActuationCommand(
                command_id=f"cmd-{uuid.uuid4().hex[:8]}",
                command_type="gcode",
                raw_command=f"G1 Z{z:.2f} F{feedrate * 0.5:.0f}",
                expected_duration_ms=800,
                safety_level=safety,
                reversible=True,
                reverse_command=f"G0 Z{envelope.z_max * 0.9:.2f}",
                parameters={"z": z, "position": {"z": z}},
            ))

        elif action == "home":
            commands.append(ActuationCommand(
                command_id=f"cmd-{uuid.uuid4().hex[:8]}",
                command_type="gcode",
                raw_command="G28",
                expected_duration_ms=5000,
                safety_level=SafetyLevel.SAFE,
                reversible=False,
                parameters={"position": {"x": 0.0, "y": 0.0, "z": 0.0}},
            ))

        elif action == "set_temperature":
            temp = params.get("temperature_c", 0)
            if temp > envelope.max_temp_c:
                return []  # Refuse
            commands.append(ActuationCommand(
                command_id=f"cmd-{uuid.uuid4().hex[:8]}",
                command_type="gcode",
                raw_command=f"M104 S{temp:.0f}",
                expected_duration_ms=100,
                safety_level=(
                    SafetyLevel.SAFE if temp <= envelope.max_temp_c * 0.8
                    else SafetyLevel.CAUTION
                ),
                reversible=True,
                reverse_command="M104 S0",
                parameters={"temperature_c": temp},
            ))

        return commands


# ── UAHP-A Engine ─────────────────────────────────────────────────────────────

class UAHPActuation:
    """
    The main UAHP-A engine.

    Manages the complete lifecycle of physical actuation:
    intent → plan → authorize → execute → receipt.

    Every step is verified, bounded, and auditable.

    Usage:
        from uahp_a import UAHPActuation, SimulationDriver, SafetyEnvelope

        driver = SimulationDriver()
        driver.connect()

        engine = UAHPActuation(
            agent_uid="agent_123",
            signing_key="secret_key",
            driver=driver,
            safety_envelope=SafetyEnvelope(),
        )

        # Create an actuation intent
        intent = engine.create_intent(
            description="Move arm to pick position",
            parameters={"action": "move", "x": 100, "y": 200, "z": 50},
            actuator_family="gcode",
        )

        # Plan, authorize, and execute
        plan = engine.plan(intent)
        engine.authorize(plan)
        receipt = engine.execute(plan)

        print(receipt.success)
        print(receipt.sensor_readings)
    """

    def __init__(
        self,
        agent_uid: str,
        signing_key: str,
        driver: ActuatorDriver,
        safety_envelope: Optional[SafetyEnvelope] = None,
        # UAHP trust score (injected from UAHPCore)
        trust_score: float = 0.5,
        # POLIS standing score (injected from POLISClient)
        standing_score: float = 50.0,
    ):
        self.agent_uid = agent_uid
        self.signing_key = signing_key
        self.driver = driver
        self.envelope = safety_envelope or SafetyEnvelope()
        self.trust_score = trust_score
        self.standing_score = standing_score
        self._receipts: List[ActuationReceipt] = []
        self._plans: Dict[str, ActuationPlan] = {}

    def _sign(self, content: str) -> str:
        """UAHP-compatible HMAC signature."""
        import hmac
        return hmac.new(
            self.signing_key.encode(),
            content.encode(),
            hashlib.sha256,
        ).hexdigest()

    def create_intent(
        self,
        description: str,
        parameters: Dict[str, Any],
        actuator_family: str = ActuatorFamily.GCODE,
        target_actuator: str = "default",
        priority: int = 5,
        timeout_s: float = 30.0,
        requires_confirmation: bool = False,
    ) -> ActuationIntent:
        """Create an actuation intent (what the agent wants to do)."""
        return ActuationIntent(
            intent_id=f"intent-{uuid.uuid4().hex[:12]}",
            agent_uid=self.agent_uid,
            timestamp=time.time(),
            description=description,
            target_actuator=target_actuator,
            actuator_family=actuator_family,
            parameters=parameters,
            priority=priority,
            timeout_s=timeout_s,
            requires_confirmation=requires_confirmation,
        )

    def plan(self, intent: ActuationIntent) -> ActuationPlan:
        """
        Translate an intent into an executable plan.
        Performs safety checks against the envelope.
        """
        # Route to the appropriate translator
        if intent.actuator_family == ActuatorFamily.GCODE:
            commands = GCodeTranslator.translate(intent, self.envelope)
        else:
            # Default: pass through as a single raw command
            commands = [ActuationCommand(
                command_id=f"cmd-{uuid.uuid4().hex[:8]}",
                command_type=intent.actuator_family,
                raw_command=json.dumps(intent.parameters),
                expected_duration_ms=1000,
                safety_level=SafetyLevel.CAUTION,
                reversible=False,
                parameters=intent.parameters,
            )]

        if not commands:
            raise ValueError(
                f"Safety envelope rejected intent: {intent.description}. "
                f"Parameters outside safety limits."
            )

        # Determine overall safety level (worst case across all commands)
        safety_order = [
            SafetyLevel.SAFE, SafetyLevel.CAUTION,
            SafetyLevel.RESTRICTED, SafetyLevel.PROHIBITED,
        ]
        worst_safety = SafetyLevel.SAFE
        for cmd in commands:
            cmd_safety = SafetyLevel(cmd.safety_level) if isinstance(cmd.safety_level, str) else cmd.safety_level
            if safety_order.index(cmd_safety) > safety_order.index(worst_safety):
                worst_safety = cmd_safety

        total_duration = sum(c.expected_duration_ms for c in commands)
        reversible = all(c.reversible for c in commands)

        plan = ActuationPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:12]}",
            intent_id=intent.intent_id,
            agent_uid=intent.agent_uid,
            created_at=time.time(),
            commands=commands,
            overall_safety=worst_safety,
            estimated_duration_ms=total_duration,
            estimated_energy_j=total_duration * 0.001 * 50,  # ~50W estimate
            reversible=reversible,
        )

        self._plans[plan.plan_id] = plan
        return plan

    def authorize(self, plan: ActuationPlan) -> bool:
        """
        Authorize a plan for execution.

        Checks:
        1. Agent trust score meets minimum for physical actuation
        2. POLIS standing allows physical operations
        3. Safety level doesn't require human confirmation

        Returns True if authorized.
        """
        # Trust gate
        min_trust = 0.4  # Higher threshold for physical actions
        if self.trust_score < min_trust:
            plan.status = ActuationStatus.FAILED
            return False

        # Standing gate
        min_standing = 50.0  # Must be at least "Recognized" standing
        if self.standing_score < min_standing:
            plan.status = ActuationStatus.FAILED
            return False

        # Safety gate
        if plan.overall_safety == SafetyLevel.PROHIBITED:
            plan.status = ActuationStatus.FAILED
            return False

        if plan.overall_safety == SafetyLevel.RESTRICTED:
            # Would need human confirmation in production
            plan.status = ActuationStatus.FAILED
            return False

        # Sign the authorization
        auth_content = f"{plan.plan_id}:{plan.agent_uid}:{time.time()}"
        plan.authorization_signature = self._sign(auth_content)
        plan.status = ActuationStatus.AUTHORIZED
        return True

    def execute(self, plan: ActuationPlan) -> ActuationReceipt:
        """
        Execute an authorized plan on the physical actuator.

        Sends commands sequentially, collecting sensor readings
        at each step. Produces a signed receipt of the outcome.
        """
        if plan.status != ActuationStatus.AUTHORIZED:
            raise ValueError(f"Plan must be authorized before execution. Current status: {plan.status}")

        if not self.driver.is_connected():
            raise ConnectionError("Actuator driver is not connected")

        plan.status = ActuationStatus.EXECUTING
        start_time = time.time()
        commands_executed = 0
        errors = []
        all_readings = {}

        for cmd in plan.commands:
            try:
                success, readings = self.driver.execute(cmd)
                if success:
                    commands_executed += 1
                    all_readings.update(readings)
                else:
                    error_msg = readings.get("error", "unknown error")
                    errors.append(f"Command {cmd.command_id}: {error_msg}")
                    # Abort on first failure
                    plan.status = ActuationStatus.FAILED
                    break
            except Exception as e:
                errors.append(f"Command {cmd.command_id}: {str(e)}")
                plan.status = ActuationStatus.FAILED
                # Emergency stop on exception
                try:
                    self.driver.emergency_stop()
                except Exception:
                    pass
                break

        end_time = time.time()

        if not errors:
            plan.status = ActuationStatus.COMPLETED

        # Final sensor reading
        try:
            final_readings = self.driver.read_sensors()
            all_readings["final"] = final_readings
        except Exception:
            pass

        # Generate signed receipt
        receipt_content = (
            f"{plan.plan_id}:{plan.agent_uid}:"
            f"{commands_executed}/{len(plan.commands)}:"
            f"{plan.status}:{end_time}"
        )

        receipt = ActuationReceipt(
            receipt_id=f"arcpt-{uuid.uuid4().hex[:12]}",
            intent_id=plan.intent_id,
            plan_id=plan.plan_id,
            agent_uid=plan.agent_uid,
            target_actuator=plan.commands[0].command_type if plan.commands else "unknown",
            timestamp_start=start_time,
            timestamp_end=end_time,
            status=plan.status,
            commands_executed=commands_executed,
            commands_total=len(plan.commands),
            sensor_readings=all_readings,
            errors=errors,
            energy_consumed_j=(end_time - start_time) * 50,  # ~50W estimate
            signature=self._sign(receipt_content),
        )

        self._receipts.append(receipt)
        return receipt

    def rollback(self, plan: ActuationPlan) -> Optional[ActuationReceipt]:
        """
        Attempt to reverse a completed plan.

        Executes reverse commands in reverse order.
        Only works if all commands in the plan are reversible.
        """
        if not plan.reversible:
            return None

        reverse_commands = []
        for cmd in reversed(plan.commands):
            if cmd.reverse_command:
                reverse_commands.append(ActuationCommand(
                    command_id=f"rev-{cmd.command_id}",
                    command_type=cmd.command_type,
                    raw_command=cmd.reverse_command,
                    expected_duration_ms=cmd.expected_duration_ms,
                    safety_level=SafetyLevel.CAUTION,
                    reversible=False,
                    parameters=cmd.parameters,
                ))

        if not reverse_commands:
            return None

        start_time = time.time()
        commands_executed = 0
        errors = []

        for cmd in reverse_commands:
            try:
                success, _ = self.driver.execute(cmd)
                if success:
                    commands_executed += 1
                else:
                    errors.append(f"Rollback {cmd.command_id} failed")
                    break
            except Exception as e:
                errors.append(f"Rollback {cmd.command_id}: {str(e)}")
                break

        end_time = time.time()
        plan.status = ActuationStatus.ROLLED_BACK

        receipt_content = f"rollback:{plan.plan_id}:{end_time}"
        receipt = ActuationReceipt(
            receipt_id=f"arcpt-rb-{uuid.uuid4().hex[:12]}",
            intent_id=plan.intent_id,
            plan_id=plan.plan_id,
            agent_uid=plan.agent_uid,
            target_actuator="rollback",
            timestamp_start=start_time,
            timestamp_end=end_time,
            status=ActuationStatus.ROLLED_BACK,
            commands_executed=commands_executed,
            commands_total=len(reverse_commands),
            sensor_readings={},
            errors=errors,
            energy_consumed_j=(end_time - start_time) * 50,
            signature=self._sign(receipt_content),
            metadata={"rollback_of": plan.plan_id},
        )

        self._receipts.append(receipt)
        return receipt

    def receipts(self, limit: Optional[int] = None) -> List[ActuationReceipt]:
        """Retrieve actuation receipts."""
        if limit:
            return self._receipts[-limit:]
        return list(self._receipts)

    def emergency_stop(self) -> bool:
        """
        Trigger emergency stop on the connected actuator.
        Aborts all pending plans.
        """
        for plan in self._plans.values():
            if plan.status == ActuationStatus.EXECUTING:
                plan.status = ActuationStatus.ABORTED

        return self.driver.emergency_stop()
