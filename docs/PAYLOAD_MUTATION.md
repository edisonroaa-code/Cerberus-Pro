# Payload Mutation Engine

The Payload Mutation Engine enhances evasion capabilities by dynamically modifying attack payloads to bypass Web Application Firewalls (WAFs) and Intrusion Detection Systems (IDS).

## Mutation Techniques

The engine supports 7 advanced mutation techniques:

1.  **Encoding Chains**: Applies multiple layers of encoding (e.g., URL, Hex, Unicode).
2.  **Comment Injection**: Inserts random comments into SQL keywords (e.g., `SEL/**/ECT`).
3.  **Case Randomization**: Randomizes the case of SQL keywords (e.g., `SeLeCt`).
4.  **Unicode Homoglyphs**: Replaces characters with visually similar Unicode equivalents.
5.  **Whitespace Variation**: Replaces spaces with other whitespace characters (e.g., tabs, newlines).
6.  **String Concatenation**: Breaks strings into concatenated parts (e.g., `'a'||'b'`).
7.  **CHAR() Encoding**: Encodes strings using the `CHAR()` function.

## Integration

The engine is integrated into the `v4_omni_surface.py` module and is triggered when `polymorphic_payloads` is enabled in the configuration. It generates a custom payload file that is passed to SQLMap via the `--prefix` and `--suffix` arguments, customized for the detected WAF and DBMS.

## Configuration

-   `polymorphic_payloads`: Enable/disable payload mutation.
-   `wafType`: Specify the target WAF type to tailor mutations (e.g., "cloudflare", "modsecurity").
