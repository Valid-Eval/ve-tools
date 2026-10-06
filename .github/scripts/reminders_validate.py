import os, re, sys, datetime, yaml

# REMINDERS_ROOT / REMINDERS_TODAY exist so the tests can run this against fixtures; the
# workflow sets neither.
ROOT = os.environ.get('REMINDERS_ROOT', '.')

# Reminder sources: (path, list key, required per-entry fields, date field, may be empty).
# credential-rotations.yml stays credential-only; compliance reviews live in their own file.
# Keep in step with SOURCES in reminders_check.py. Compliance reviews retire, so that file
# may be absent, empty, or have an empty list; none of those may stop credential reminders.
# (A malformed compliance file still fails validation.)
SOURCES = [
    ('.github/credential-rotations.yml', 'credentials',
     ('name', 'description', 'expires', 'rotation_steps'), 'expires', False),
    ('.github/compliance-reviews.yml', 'reviews',
     ('name', 'description', 'due', 'steps', 'compliance_ref', 'jira_ref'), 'due', True),  # may be empty or absent
]
# Shape checks for the compliance links rendered into notifications.
FIELD_PATTERNS = {
    'jira_ref': (r'[A-Z][A-Z0-9]+-\d+', 'a Jira key like INF-382'),
    'compliance_ref': (r'https://\S+', 'an https:// URL'),
}

# Anything outside these sets is rejected, so a typo (reviewz:, remind_day_before:) fails loudly
# instead of being ignored and silently falling back to a default.
TOP_LEVEL_KEYS = ('email_to', 'email_from', 'jira_project')
OPTIONAL_ENTRY_KEYS = ('remind_days_before', 'jira_priority', 'notes')
STRING_OPTIONAL_KEYS = ('jira_priority', 'notes')
JIRA_PRIORITIES = ('Highest', 'High', 'Medium', 'Low', 'Lowest')
EMAIL = r'[^@\s]+@[^@\s]+\.[^@\s]+'
JIRA_PROJECT = r'[A-Z][A-Z0-9]+'
ISO_DATE = r'\d{4}-\d{2}-\d{2}'  # fromisoformat() also accepts the compact 20261020 form on 3.11+

errors = []
today = datetime.date.fromisoformat(os.environ['REMINDERS_TODAY']) if os.environ.get('REMINDERS_TODAY') else datetime.date.today()

for config_path, list_key, required_fields, date_field, may_be_empty in SOURCES:
    config_path = os.path.normpath(os.path.join(ROOT, config_path))
    if may_be_empty and not os.path.exists(config_path):
        print(f"OK: {config_path} not present (no {list_key} scheduled; none will be sent)")
        continue

    # --- Parse YAML ---
    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        print(f"FATAL: cannot read {config_path} as YAML:\n{e}")
        sys.exit(1)

    if config is None and may_be_empty:
        # Zero-byte or comments-only file
        print(f"OK: {config_path} is empty (no {list_key} scheduled; none will be sent)")
        continue

    if not isinstance(config, dict):
        print(f"FATAL: {config_path} must contain a YAML mapping, got {type(config).__name__}")
        sys.exit(1)

    unknown = sorted(set(config) - set(TOP_LEVEL_KEYS) - {list_key})
    if unknown:
        errors.append(f"{config_path}: unknown top-level key(s) {unknown} (expected {list(TOP_LEVEL_KEYS) + [list_key]})")

    entries = config.get(list_key)
    if entries is None and list_key not in config and may_be_empty and not unknown:
        # A mapping with routing fields but no list key at all: nothing scheduled.
        entries = []
    if not isinstance(entries, list) or (len(entries) == 0 and not may_be_empty):
        hint = f" (write '{list_key}: []' to schedule nothing)" if may_be_empty else ''
        errors.append(f"{config_path}: '{list_key}' must be a {'list' if may_be_empty else 'non-empty list'}, got {type(entries).__name__}{hint}")
        continue

    # --- Top-level routing fields (only needed when there is something to send) ---
    if entries or not may_be_empty:
        for field in ('email_to', 'email_from', 'jira_project'):
            value = config.get(field)
            if not value:
                errors.append(f"{config_path}: missing top-level field: '{field}'")
            elif not isinstance(value, str):
                errors.append(f"{config_path}: '{field}' must be a string, got {type(value).__name__}")
            else:
                pattern, what = (JIRA_PROJECT, 'an uppercase Jira project key like INF') if field == 'jira_project' \
                    else (EMAIL, 'an email address')
                if not re.fullmatch(pattern, value):
                    errors.append(f"{config_path}: '{field}' must be {what} (got '{value}')")

    # --- Per-entry validation ---
    seen_names = set()
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"{config_path}: {list_key}[{i}] must be a mapping")
            continue
        label = entry.get('name', f'{list_key}[{i}]')

        known = set(required_fields) | set(OPTIONAL_ENTRY_KEYS)
        unknown_keys = sorted(set(entry) - known)
        if unknown_keys:
            errors.append(f"{label}: unknown key(s) {unknown_keys} (known: {sorted(known)})")

        for field in STRING_OPTIONAL_KEYS:
            if field in entry and not isinstance(entry[field], str):
                errors.append(f"{label}: '{field}' must be a string, got {type(entry[field]).__name__}"
                              + (' (quote dates)' if field == 'notes' else ''))
        if isinstance(entry.get('jira_priority'), str) and entry['jira_priority'] not in JIRA_PRIORITIES:
            errors.append(f"{label}: 'jira_priority' must be one of {list(JIRA_PRIORITIES)} (got '{entry['jira_priority']}')")

        for field in required_fields:
            value = entry.get(field)
            if not value:
                errors.append(f"{label}: missing required field '{field}'")
            elif not isinstance(value, str):
                hint = ' (quote dates: "YYYY-MM-DD")' if field == date_field else ''
                errors.append(f"{label}: '{field}' must be a string, got {type(value).__name__}{hint}")

        for field, (pattern, what) in FIELD_PATTERNS.items():
            value = entry.get(field)
            if field in required_fields and isinstance(value, str) and not re.fullmatch(pattern, value):
                errors.append(f"{label}: '{field}' must be {what} (got '{value}')")

        # Validate name contains only safe characters, and is unique (it forms the dedup title)
        name = entry.get('name', '')
        if isinstance(name, str) and name:
            if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
                errors.append(f"{list_key}[{i}]: 'name' must contain only alphanumeric characters, hyphens, and underscores (got {name!r})")
            if name in seen_names:
                errors.append(f"{label}: duplicate name in {config_path}")
            seen_names.add(name)

        # Validate the date field is a parseable ISO date
        date_raw = entry.get(date_field, '')
        if isinstance(date_raw, str) and date_raw:
            try:
                if not re.fullmatch(ISO_DATE, date_raw):
                    raise ValueError(date_raw)
                date = datetime.date.fromisoformat(date_raw)
                days_left = (date - today).days
                if days_left < 0:
                    print(f"WARNING: {label} {date_field} date passed {abs(days_left)} days ago ({date_raw})")
                else:
                    print(f"OK: {label} — {date_field} {date_raw} ({days_left} days from now)")
            except ValueError:
                errors.append(f"{label}: '{date_field}' value '{date_raw}' is not a valid ISO date (expected YYYY-MM-DD)")

        # Validate remind_days_before is a positive integer if present
        if 'remind_days_before' in entry:
            rdb = entry['remind_days_before']
            if not isinstance(rdb, int) or isinstance(rdb, bool) or rdb <= 0:
                errors.append(f"{label}: 'remind_days_before' must be a positive integer (got '{rdb}')")

    print(f"{config_path}: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} under '{list_key}' checked")

if errors:
    print(f"\n{len(errors)} validation error(s):")
    for e in errors:
        print(f"  ERROR: {e}")
    sys.exit(1)
else:
    print("\nAll reminder entries validated successfully")
