# Security policy

## Supported versions

Security fixes land on the current release candidate line and on `main`.
Older tags are not maintained.

## Reporting a vulnerability

Do not open a public issue. Use the repository's **Security** tab and
**Report a vulnerability** so the report stays private. Include:

- the affected version or commit;
- the request, push, or CLI invocation that triggers it;
- the impact (data exposure, privilege escalation, denial of service);
- a minimal reproduction, if one exists.

You will get an acknowledgement, a severity assessment, and a fix or
mitigation plan. Please give us time to ship a fix before public disclosure.

## Scope

In scope: authentication and authorization, session and checkpoint privacy,
git transport and ref policy, CI runner and sandbox isolation, secret
handling, and the web/API surface. Out of scope: findings that require a
compromised host, a malicious site administrator, or a deliberately
misconfigured deployment (for example, a public instance with open
registration and no rate limits).
