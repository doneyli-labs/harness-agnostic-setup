"""Canonical discovery and direct-execution runner for foundation tests."""
import unittest

from cases_foundation import (
    CapabilityGateTests,
    DescriptorWalkTests,
    ValidationAndLedgerTests,
)
from cases_core_analysis import CoreAnalysisTests
from cases_core_bootstrap import CoreBootstrapTests
from cases_core_report import CoreReportTests
from cases_input_policy import InputPolicyTests
from cases_integration import IntegrationTests
from cases_inventory import InventoryTests
from cases_output_refusal import OutputRefusalTests
from cases_traversal import TraversalTests

__all__ = (
    "CapabilityGateTests",
    "CoreAnalysisTests",
    "CoreBootstrapTests",
    "CoreReportTests",
    "DescriptorWalkTests",
    "ValidationAndLedgerTests",
    "InputPolicyTests",
    "IntegrationTests",
    "InventoryTests",
    "OutputRefusalTests",
    "TraversalTests",
)


if __name__ == "__main__":
    unittest.main()
