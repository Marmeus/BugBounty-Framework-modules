### Assetfinder Configuration (`assetfinder.env`)

This file contains environment variables for assetfinder API integrations. The file uses a simple `KEY=value` format (one per line).

**Required keys:**
- `FB_APP_ID`: Facebook App ID (for Facebook source)
- `FB_APP_SECRET`: Facebook App Secret (for Facebook source)
- `VT_API_KEY`: VirusTotal API Key (for VirusTotal source)
- `SPYSE_API_TOKEN`: Spyse API Token (for findsubdomains source)

**Example:**
```bash
FB_APP_ID=your_facebook_app_id
FB_APP_SECRET=your_facebook_app_secret
VT_API_KEY=your_virustotal_api_key
SPYSE_API_TOKEN=your_spyse_api_token
```

**Notes:**
- Empty values are allowed - assetfinder will work with limited sources if API keys are not provided
- Lines starting with `#` are treated as comments
- Get Facebook credentials from: https://developers.facebook.com/
- Get VirusTotal API key from: https://developers.virustotal.com/reference
- Get Spyse API token from: https://spyse.com/apidocs

### Subfinder Configuration (`subfinder-config.yaml`)

This file contains the subfinder provider configuration in YAML format. It configures API keys for various subdomain discovery sources.

**Example:**
```yaml
binaryedge:
  - [api_key_here]

censys:
  - [api_id_here]
  - [api_secret_here]

certspotter:
  - [api_key_here]

chaos:
  - [api_key_here]

dnsdb:
  - [api_key_here]

fofa:
  - [email_here]
  - [api_key_here]

github:
  - [github_token_here]

intelx:
  - [api_key_here]

passivetotal:
  - [username_here]
  - [api_key_here]

securitytrails:
  - [api_key_here]

shodan:
  - [api_key_here]

urlscan:
  - [api_key_here]

virustotal:
  - [api_key_here]

zoomeye:
  - [api_key_here]
```

**Notes:**
- The file can be empty or minimal - subfinder will work without it but with limited sources
- For detailed configuration options, see: https://github.com/projectdiscovery/subfinder
- The configuration file is optional - subfinder will use default sources if not provided

