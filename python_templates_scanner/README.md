# Quick Start - Running Checks Locally

## Execution
### Use the Helper Script (Recommended)

```bash
python3 run_check.py <check_file> --ip <ip> --port <port> --fqdn <fqdn> [--ssl]
```

### Direct Execution

You can also run files directly, but you need to set PYTHONPATH first:

```bash
# Set PYTHONPATH where the odin librarand run (one line)
PYTHONPATH="${PWD}" python3 checks/RECON/sensitive_paths_check.py --ip 192.168.1.1 --port 80 --fqdn example.com --ssl False
```

> **Note:** 
> - You must set `PYTHONPATH` so Python can find the `odin` module
> - The `--ssl` argument parsing has a limitation: any non-empty string becomes `True` due to argparse's `type=bool` behavior
> - The helper script (`run_check.py`) fixes both issues automatically

## What You'll See

```bash
[+] Loading check from: RECON/fortios_admin_panel.py
[+] Running check on http://example.com
[+] Found 1 result(s):
  [1] CheckResult(url='http://example.com/login')
```





# Debugging Odin Checks Locally

## 1. Add Print Statements

You can add print statements in your check's `check()` method:

```python
def check(self):
    results = []
    url = self.target.as_url('http')
    print(f'[DEBUG] Checking URL: {url}')
    # ... your check code ...
```

## 2. Test Individual Components

You can test individual parts of your check:

```python
from odin import CheckTarget, CheckResult

# Test CheckTarget
target = CheckTarget(ip='192.168.1.1', port=80, fqdn='test.com', ssl=False)
print(target.as_url('http'))  # Should print: http://test.com

# Test CheckResult
result = CheckResult(url='http://test.com/vuln', name='Test Check', severity='High')
print(result)
```

## 3. Environment Variables

Some checks use environment variables:

```bash
# Set OOB server for XXE/SSRF tests
export ODIN_OOB=your-oob-server.com
python3 run_check.py 2024/CVE-2024-22024/CVE-2024-22024.py --ip 10.0.0.1 --port 443 --fqdn target.com --ssl
```

## 4. Integration with Your Workflow

The `test_check` function from odin is designed to be called programmatically:

```python
from odin import test_check, CheckTarget
from RECON.fortios_admin_panel import Check

# Programmatic usage
test_check(Check, '192.168.1.1', 80, 'example.com', False)
```
