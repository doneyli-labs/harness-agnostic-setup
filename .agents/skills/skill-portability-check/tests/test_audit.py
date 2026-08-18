"""Canonical discovery and direct-execution runner for foundation tests."""
import unittest

from cases_foundation import (
    CapabilityGateTests,
    DescriptorWalkTests,
    ValidationAndLedgerTests,
)

__all__ = (
    "CapabilityGateTests",
    "DescriptorWalkTests",
    "ValidationAndLedgerTests",
)


if __name__ == "__main__":
    unittest.main()
