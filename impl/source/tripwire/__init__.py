"""Sandbox Escape Tripwire: a pure, deterministic decision engine.

The engine plans host decoys (`plan`) and evaluates host sensor events against a
plan's `watch` (`evaluate`). It performs no filesystem, network, or clock access;
its only ambient inputs are the SANDBOX_HONEYPOT_SEED and
SANDBOX_HONEYPOT_SENSOR_KEYS environment variables, passed in explicitly.
"""

from .engine import run

__all__ = ["run"]
