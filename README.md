# domain-intel

**Website intelligence for AI agents.** Given any URL, returns tech stack (CMS, frameworks, analytics, CDN), hosting provider, security posture, email config, SEO metadata, social profiles, and DNS records — all from a **single HTTP request**. No scraping, no third-party APIs.

## Quick Install

```json
{
  "mcpServers": {
    "domain-intel": {
      "url": "https://domain-intel.mcpize.run"
    }
  }
}
```

Or via MCPize CLI:
```bash
mcpize install domain-intel
```

## Tools

| Tool | Description |
|------|-------------|
| `website_analyze` | Comprehensive analysis: tech stack, security, SSL, email, SEO, social, WHOIS, DNS |
| `tech_detect` | Detect CMS, frameworks, analytics, CDN, hosting provider |
| `security_headers` | Check HSTS, CSP, X-Frame-Options, and 6+ other security headers |
| `email_security` | Check SPF, DKIM, DMARC records and identify email provider |

## Examples

### "What tech does Shopify use?"
```
website_analyze("https://www.shopify.com")
```
Returns: Shopify CMS, Google Analytics, Cloudflare CDN, valid SSL, HSTS enabled, SEO metadata, social media profiles (Twitter, LinkedIn, GitHub, Instagram, Facebook).

### "Is example.com's email secure?"
```
email_security("example.com")
```
Returns: SPF configured, DMARC status, MX records, email provider detection.

### "Check my site's security headers"
```
security_headers("https://mysite.com")
```
Returns: security score (0-100), which headers are present/missing, severity ratings.

## Pricing

- **Free**: 25 lookups/month
- **Pro**: $29/month for 500 lookups

## How It Works

Uses only standard internet protocols — **no scraping, no data storage, no third-party API keys**:

- HTTP GET → security headers, tech detection, SEO metadata
- DNS resolution → A, MX, NS, TXT, CNAME records + SPF/DKIM/DMARC
- TLS handshake → SSL certificate validation
- WHOIS → domain registration details

## Why domain-intel?

Sales teams, marketers, developers, and security researchers need quick answers about websites. Instead of juggling 5+ tools (Wappalyzer, SecurityHeaders.com, SSLLabs, MXToolbox, WHOIS), one MCP server gives you everything an AI agent needs.

## Links

- [Marketplace](https://mcpize.com/mcp/domain-intel)
- [Playground](https://mcpize.com/mcp/domain-intel/playground)
- [API Docs](https://mcpize.com/mcp/domain-intel/api)
