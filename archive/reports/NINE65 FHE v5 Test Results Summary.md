# NINE65 FHE v5 Test Results Summary

Date: 2026-02-05
Profile: release

## Overall Status
PASS - Workspace tests completed with zero failures.

## Summary (release)
- Unit tests:
  - mana: 30 passed
  - nine65: 424 passed, 0 ignored
  - unhal: 10 passed
- Integration/property tests (nine65): 22 passed
- Doc-tests: 2 passed, 39 ignored (mana 1, nine65 35, unhal 3)
- Serde-enabled nine65 tests: 432 passed; integration 27 passed; doc-tests 2 passed, 35 ignored
- Formal verification: lean4/KElimination lake build SUCCESS

## Notes
- All previously ignored runtime tests/benchmarks are now active.
- Doc-tests remain mostly ignored by design (see inline doc blocks).
- Serde run includes adversarial deserialization tests and key serialization roundtrips.

## Full Report
See docs/COMPREHENSIVE_TEST_REPORT_V5.md
