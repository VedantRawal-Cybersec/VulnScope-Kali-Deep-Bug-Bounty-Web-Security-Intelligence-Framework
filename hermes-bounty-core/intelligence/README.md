# Vulnerability Intelligence Layer

Maintain a broad read-only research layer separate from active target testing.

Normalize advisories, research, vendor notes, and vetted repositories into:

- technology
- affected versions/configurations
- prerequisites
- root cause
- observable behavior
- safe detection strategy
- control test
- evidence requirements
- false-positive causes
- references
- publication/update date

Never execute arbitrary public PoC repositories automatically.

Instead:
research -> normalize -> applicability check -> controlled test job -> scope gateway -> evidence -> validation.

Recommended source classes:
- CVE/NVD/CISA
- vendor advisories
- OWASP
- PortSwigger research
- framework release/security notes
- academic/security conference material
- established security research blogs
- vetted GitHub security research repositories
