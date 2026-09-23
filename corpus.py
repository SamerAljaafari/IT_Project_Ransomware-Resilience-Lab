"""Deterministic business-text corpus used by the dataset generator.

All content is drawn from fixed word lists so that a given seed always
produces byte-identical text. Nothing here uses `random` directly -- every
function takes an explicit `random.Random` instance.
"""

DEPARTMENTS = [
    "Finance", "Human Resources", "Operations", "Legal", "Procurement",
    "IT Services", "Facility Management", "Sales", "Marketing", "Logistics",
]

SUBJECTS = [
    "quarterly budget", "headcount planning", "vendor contract", "risk assessment",
    "service level agreement", "cost centre allocation", "audit finding",
    "capacity forecast", "invoice reconciliation", "training programme",
    "compliance review", "asset inventory", "project milestone",
    "maintenance window", "procurement request", "travel expense report",
]

VERBS = [
    "reviewed", "approved", "escalated", "deferred", "consolidated", "audited",
    "revised", "submitted", "rejected", "archived", "forwarded", "clarified",
]

QUALIFIERS = [
    "in accordance with the internal guideline", "pending confirmation by the department head",
    "subject to the agreed budget ceiling", "as discussed in the steering committee",
    "before the end of the current fiscal quarter", "without further amendments",
    "following the recommendation of the auditor", "under the existing framework agreement",
    "with reference to the previous correspondence", "once the responsible party has replied",
]

CONNECTORS = [
    "Furthermore,", "In addition,", "However,", "Consequently,", "For this reason,",
    "As a result,", "Nevertheless,", "In summary,", "Accordingly,", "Meanwhile,",
]

FIRST_NAMES = [
    "Anna", "Michael", "Sophie", "Thomas", "Julia", "Daniel", "Laura", "Stefan",
    "Nina", "Markus", "Clara", "Peter", "Eva", "Jonas", "Lena", "Andreas",
]

LAST_NAMES = [
    "Weber", "Schneider", "Fischer", "Meyer", "Wagner", "Becker", "Hoffmann",
    "Schulz", "Koch", "Richter", "Klein", "Wolf", "Neumann", "Braun",
]

COMPANIES = [
    "Nordwind Logistik GmbH", "Auriga Systems AG", "Behrend & Partner",
    "Kestrel Consulting", "Vitex Handels GmbH", "Lindmark Industrie AG",
    "Orbis Facility Services", "Rheinbach Technik GmbH",
]

CITIES = [
    "Hamburg", "Muenchen", "Koeln", "Leipzig", "Stuttgart", "Bremen",
    "Hannover", "Dresden", "Nuernberg", "Essen",
]

STATUSES = ["open", "closed", "pending", "approved", "rejected", "in review"]

COST_CENTRES = [f"CC-{n:04d}" for n in range(1000, 1040)]

LOG_TEMPLATES = [
    "session opened for user {user} from host {host}",
    "batch job {job} completed with status {status}",
    "record {rid} written to table {table}",
    "connection to {host} re-established after timeout",
    "export of {n} rows finished in {ms} ms",
    "validation passed for document {rid}",
    "scheduled task {job} queued by service account",
    "cache refreshed, {n} entries invalidated",
]


def sentence(rng):
    """One plausible business sentence."""
    return (
        f"{rng.choice(CONNECTORS)} the {rng.choice(SUBJECTS)} was "
        f"{rng.choice(VERBS)} by {rng.choice(FIRST_NAMES)} "
        f"{rng.choice(LAST_NAMES)} {rng.choice(QUALIFIERS)}."
    )


def paragraph(rng, min_s=3, max_s=7):
    return " ".join(sentence(rng) for _ in range(rng.randint(min_s, max_s)))


def person(rng):
    return f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}"


def log_line(rng, seq, ts):
    tmpl = rng.choice(LOG_TEMPLATES)
    return f"{ts} [{rng.choice(['INFO', 'INFO', 'INFO', 'WARN', 'DEBUG'])}] seq={seq} " + tmpl.format(
        user=rng.choice(FIRST_NAMES).lower(),
        host=f"srv-{rng.randint(1, 40):02d}.corp.local",
        job=f"JOB_{rng.randint(100, 999)}",
        status=rng.choice(["OK", "OK", "OK", "RETRY"]),
        rid=f"R{rng.randint(100000, 999999)}",
        table=rng.choice(["INVOICE", "LEDGER", "STAFF", "ASSET", "ORDER"]),
        n=rng.randint(10, 50000),
        ms=rng.randint(5, 9000),
    )
