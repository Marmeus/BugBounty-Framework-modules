# Bug Bounty Framework Modules

A collection of containerized  security testing tools packaged as Docker containers. Each module performs a specific security testing task (OSINT, vulnerability scanning, secret detection, etc.) and follows a standardized interface for input/output processing.



## Module Types

Modules are categorized into two types:

- **IG (Information Gathering)**: Passive and active reconnaissance modules
- **EX (Execution)**: Vulnerability scanning and exploitation modules

## Available Modules

### OSINT & Domain Discovery

- **`osint_domains_amass`** - Domain discovery using Amass
- **`osint_domains_curl`** - Domain discovery using curl-based techniques
- **`osint_domains_tools`** - Domain discovery using Subfinder and Assetfinder
- **`osint_urls_gau`** - URL discovery using GAU (Get All URLs)
- **`dns_brute_force`** - DNS subdomain brute-forcing
- **`resolve_domains`** - DNS resolution for discovered domains

### Vulnerability Scanning

- **`nuclei_templates_scanner`** - Vulnerability scanning using Nuclei templates
- **`python_templates_scanner`** - Custom Python-based security checks
- **`mantra_find_secrets`** - Secret and API key detection

### Service & URL Discovery

- **`service_info`** - Service information gathering (HTTPx, screenshots, open ports)
- **`url_gather_active`** - Active URL discovery and gathering



## Building Modules

### Build

```bash
./build_modules.sh [-l] [<osint_domains_tools>] 
```

### Custom Image Registry

By default, images are tagged with the `worker` registry prefix. You can override this:

```bash
IMAGE_REGISTRY=myregistry ./build_modules.sh
```



## Uploading Modules Automatically

You can upload the `module.yaml` file into the infra through the `https://front.example.com:5000/modules` panel. However, this can be a tidious task, so you can use this Python script to upload all them automatically.:

```bash
python3 upload_modules.py --url https://front.example.com
```

### Upload Options

- `--url`: FRONT application URL (default: from `FRONT_URL` env var or `https://localhost:5000`)
- `--modules-dir`: Directory containing modules (default: script's parent directory)
- `--include-test`: Also upload `t_module.yaml` files (test modules)
- `--dry-run`: Show what would be uploaded without actually uploading

### Example

> :warning: **Note**: The upload script disables SSL/TLS certificate verification for development environments. This should only be used in trusted environments.

```bash
# Upload all modules
python3 upload_modules.py --url https://front.example.com

# Dry run to see what would be uploaded
python3 upload_modules.py --url https://front.example.com --dry-run

# Upload including test modules
python3 upload_modules.py --url https://front.example.com --include-test
```





# Module Development

## Creating a New Module

1. Create a new directory for your module
2. Add a `Dockerfile` with the required dependencies
3. Create `module.yaml` with module configuration
4. Implement `runner.py` that:
   - Reads from `/task/input.json`
   - Writes results to `/task/output.ndjson` (NDJSON format)
   - Writes errors to `/task/errors.txt`
5. Test locally, then build and upload



## Module Requirements

- Must read input from `/task/input.json`
- Must write output to `/task/output.ndjson` in NDJSON format
- Must write errors/warnings to `/task/errors.txt`
- Must exit with code 0 on success, non-zero on failure
- Should handle timeouts gracefully
- Should respect scope rules and filtering parameters



## Module Structure

Each module follows a consistent structure:

```
module_name/
├── Dockerfile         # Container definition
├── module.yaml        # Module configuration and metadata
├── <runner.py>         # Main execution script
└── [other files]      # Module-specific files
```



## Module Configuration (`module.yaml`)

Each module defines its configuration in a `module.yaml` file:

```yaml
schema_version: 1
name: module_name
type: IG|EX
tags: ["tag1", "tag2"]
image: worker/module_name:latest
pull_policy: never
entrypoint: ["python3", "/app/runner.py"]
timeout_seconds: 3600
resources:
  memory: 1g
  cpu_priority: 1.0
input_type: domain|url|service
output_type: domain|url|service|issue
impact: low|medium|high
io:
  input_file: /task/input.json
  output_file: /task/output.ndjson
  errors_file: /task/errors.txt
```



## Module Execution

Modules are executed as Docker containers with the following interface:

### Input

Modules read task data from `/task/input.json`:

```json
{
  "program_id": "program_123",
  "params": {
    "domains": ["example.com"],
    "in_scope_rules": ["*.example.com"],
    "out_scope_rules": ["*.out.example.com"],
    "max_level": 2
  }
}
```

### Output

Modules write results to `/task/output.ndjson` in NDJSON format (one JSON object per line):

```json
{"host": "subdomain.example.com", "program_id": "program_123", "in_scope": true, "level": 1}
{"host": "another.example.com", "program_id": "program_123", "in_scope": true, "level": 2}
```

### Errors

Errors and warnings are written to `/task/errors.txt`.





# License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

When contributing new modules:

1. Follow the existing module structure
2. Include appropriate error handling
3. Document any required API keys or configuration
4. Test modules thoroughly before submitting
5. Update this README with module details if adding a new category

## Support

For issues, questions, or contributions, please refer to the main Bug Bounty Framework documentation or contact the maintainers.

