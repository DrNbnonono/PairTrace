# Ethics, scope and coordinated disclosure

PairTrace exists to study **defensive authorization correctness** in authorized systems.

- Test only owned infrastructure, local labs or targets with explicit written authorization and an agreed scope.
- No internet-wide live probing, credential brute force, account takeover, session hijacking or collection of other users' traffic.
- Use mock tools and inert sentinel data rather than real credentials, production repositories, personal messages or destructive commands.
- Keep test ports on loopback by default; disable outbound network for deliberately vulnerable historical versions.
- Exclude secrets, live pairing codes, session tokens, message bodies, personal data and raw production captures from commits, issues and CI.
- For a suspected real flaw: validate product version and intended behavior, minimize the reproducer, privately report to the maintainer, respect embargo/coordination, publish only with authorization.
- A finding is not a CVE; a synthetic policy violation is not a finding in a deployed implementation.
