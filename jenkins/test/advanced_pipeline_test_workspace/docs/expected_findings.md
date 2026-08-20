# Expected Scanner Findings

This workspace should trigger these scanner checks:

- SECRET001: hardcoded password, api key, token
- SEC101: eval usage
- SEC103: shell=True usage
- ERR101: bare except
- DBG101: print or console debug output
- TODO101: TODO/FIXME comments
- SIZE101: large_file.py is intentionally large
- CPLX101: complex_module.py may trigger rough complexity depending on scoring
- Low coverage: coverage.xml has 42 percent line rate
- Test failure rate: JUnit report has failures and errors
