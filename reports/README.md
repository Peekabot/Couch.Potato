# Reports Directory

Store all your vulnerability reports organized by platform.

## Directory Structure

```
reports/
├── intigriti/          # Intigriti submissions
│   ├── company-a/
│   │   ├── INTG-2025-12-01-xss.md
│   │   └── INTG-2025-12-02-idor.md
│   └── company-b/
├── hackerone/          # HackerOne submissions
│   ├── program-x/
│   └── program-y/
├── bugcrowd/           # Bugcrowd submissions
│   ├── company-c/
│   └── company-d/
└── other/              # Other platforms
    └── yeswehack/
```

## Naming Convention

Use this format for report files:

```
[PLATFORM-CODE]-[YYYY-MM-DD]-[VULN-TYPE].md
```

**Examples:**
- `INTG-2025-12-30-xss.md` - Intigriti XSS report
- `H1-2025-12-30-idor.md` - HackerOne IDOR report
- `BC-2025-12-30-sqli.md` - Bugcrowd SQLi report

## Organizing Reports

### By Program
Create a folder for each company/program:

```
reports/intigriti/
├── acme-corp/
│   ├── INTG-2025-01-15-xss.md
│   └── INTG-2025-02-20-csrf.md
└── example-inc/
    └── INTG-2025-03-10-idor.md
```

### Include PoCs
Store PoC files alongside reports:

```
acme-corp/
├── INTG-2025-01-15-xss.md
├── INTG-2025-01-15-xss-poc.html
└── screenshots/
    ├── step1.png
    └── step2.png
```

## Report Status

Add status to filename or use git tags:

```
INTG-2025-12-30-xss.md              # Submitted
INTG-2025-12-30-xss-ACCEPTED.md     # Accepted
INTG-2025-12-30-xss-DUPLICATE.md    # Duplicate
```

## Before Committing

⚠️ **IMPORTANT**: Redact sensitive information!

- [ ] Remove real credentials
- [ ] Sanitize PII (Personal Identifiable Information)
- [ ] Redact internal IPs/infrastructure
- [ ] Remove session tokens
- [ ] Blur sensitive screenshots
- [ ] Wait until disclosure is allowed

## Template Usage

1. Copy template from `/templates/`
2. Rename with proper convention
3. Fill in all sections
4. Save in appropriate directory
5. Update `SUBMISSION_TRACKER.md`

## Tips

- One report per file
- Use descriptive names
- Keep PoCs sanitized
- Document everything
- Update tracker after submission
