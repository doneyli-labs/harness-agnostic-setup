"""Canonical discovery and direct-execution runner for foundation tests."""
import unittest

from cases_foundation import (
    CapabilityGateTests,
    DescriptorWalkTests,
    ValidationAndLedgerTests,
)
from cases_input_policy import InputPolicyTests
from cases_output_refusal import OutputRefusalTests
from cases_traversal import TraversalTests

__all__ = (
    "CapabilityGateTests",
    "DescriptorWalkTests",
    "ValidationAndLedgerTests",
    "InputPolicyTests",
    "OutputRefusalTests",
    "TraversalTests",
)


if __name__ == "__main__":
    unittest.main()
