# Security Policy

## Reporting

Report vulnerabilities responsibly to the repository owner by email to **g@abejar.net** -- do not open public issues.

## Scope

Defensive SOC analysis tool. Use against logs you are authorized to access.

## Considerations

- Event metadata (IPs, usernames, hostnames) is forwarded to the LLM endpoint configured in `llm_client.py` -- evaluate data-handling requirements
- Elasticsearch translator uses your existing ES auth -- review the index pattern and ACLs
- Generated NL->query results should always be validated against expected schema before execution against production indexes
