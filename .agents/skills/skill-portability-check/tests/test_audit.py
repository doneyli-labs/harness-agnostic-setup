"""Canonical discovery and direct-execution runner for foundation tests."""
import unittest

from cases_foundation import (
    CapabilityGateTests,
    DescriptorWalkTests,
    ValidationAndLedgerTests,
)
from cases_input_policy import InputPolicyTests

__all__ = (
    "CapabilityGateTests",
    "DescriptorWalkTests",
    "ValidationAndLedgerTests",
    "InputPolicyTests",
)


if __name__ == "__main__":
    unittest.main()
