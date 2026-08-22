"""
Runtime configuration.

A bank cannot deploy a SOC whose risk appetite is a Python literal. Which
regulators it answers to, how many failed logins it treats as an attack, how
long its analysts actually take per alert, which containment actions it is
willing to let a machine perform unattended — every one of those differs by
institution, and none of them is a code change.

So they live in one JSON file, described by the schema below. The schema is the
half that matters: each setting carries the plain-English question it answers,
its bounds, and a sentence on what observably changes when you move it. That is
what lets the console render a usable form without anyone reading this source,
and what lets the API reject a bad value with a message an operator can act on.

Three rules this module exists to enforce.

1.  **Read at the point of use, never at import.**
    A constant captured at import time needs a process restart to change, which
    defeats the entire point. Everything goes through `get()`, and `get()`
    re-reads the file when it changes on disk.

2.  **An invalid configuration is rejected whole.**
    Half-applied settings are worse than rejected ones, because the operator
    believes the state they are shown. `validate()` collects every error before
    anything is written.

3.  **Only differences from default are stored.**
    The file holds overrides, not a full snapshot. That makes "what has been
    changed here" answerable by comparison rather than by memory, and means a
    later release can add or re-tune a default without silently inheriting an
    old one.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "soc_config.json"
AUDIT_PATH = ROOT / "soc_config_audit.json"

#: How many change records to keep. Enough to answer "what did we touch during
#: the demo", not an audit system.
AUDIT_LIMIT = 40

SEVERITIES = ["critical", "high", "medium", "low"]

#: The confidence at which detection_fusion calls a verdict "malicious". Not a
#: setting — it is the definition of the word — but validation needs it, because
#: a configurable confidence ceiling set below it silently removes the verdict.
MALICIOUS_VERDICT_THRESHOLD = 0.85

# The kill-chain stage ordering mirrors layer_2_detection/mitre_mapper.py. Named
# here rather than imported to keep this module free of pipeline imports — every
# layer imports *this*, so it must not import back. A test asserts they agree.
KILL_CHAIN_STAGES = [
    ("1", "Reconnaissance"),
    ("2", "Resource Development"),
    ("3", "Initial Access"),
    ("9", "Credential Access"),
    ("11", "Lateral Movement"),
    ("14", "Exfiltration"),
]

# Same arrangement for the regime ids in regulatory_clock.REGIMES.
REGIME_OPTIONS = [
    ("dora", "EU — DORA (4 hours)"),
    ("cert_in", "India — CERT-In (6 hours)"),
    ("us_banking", "US — OCC / Fed / FDIC (36 hours)"),
    ("sec_8k", "US — SEC Item 1.05 (4 business days)"),
]

RESPONSE_ACTIONS = [
    ("enrich", "Look things up — threat intel, asset owner, past incidents"),
    ("notify", "Tell people — page the on-call analyst, open a ticket"),
    ("monitor", "Watch more closely — raise logging, add a watchlist entry"),
    ("block_ip", "Block an external address at the firewall"),
    ("disable_account", "Disable a user or service account"),
    ("isolate_host", "Cut a host off the network"),
]


# ─────────────────────────────────────────────────────────────────────────────
# The schema
#
# Grouped so the console renders one card per group rather than one long form.
# Every field here is consumed by the UI: `label` is the control's question,
# `help` the sentence under it, `affects` the "what will this change" line, and
# `demo` a value that visibly moves the numbers — which is what makes a live
# before/after possible without anyone inventing one on the spot.
# ─────────────────────────────────────────────────────────────────────────────

GROUPS: list[dict[str, str]] = [
    {
        "id": "detection",
        "label": "How sensitive detection should be",
        "help": "Move these to trade missed attacks against false alarms. Every "
                "change re-scores the whole queue, so you can see the effect before you keep it.",
    },
    {
        "id": "severity",
        "label": "How serious each kind of attack is",
        "help": "Severity is a judgement about impact, and a retail bank and a "
                "custodian will not make it the same way. This is that judgement, written down.",
    },
    {
        "id": "reporting",
        "label": "Which regulators we answer to",
        "help": "Only the regimes you are actually subject to should raise a clock. "
                "Three irrelevant countdowns next to a real one trains people to ignore all four.",
    },
    {
        "id": "response",
        "label": "What the system may do on its own",
        "help": "Anything not ticked here still gets recommended — it just waits for a "
                "person to approve it. Gate on the damage the fix could do, not on how bad the attack is.",
    },
    {
        "id": "model",
        "label": "How we work out time saved",
        "help": "The hours-saved figure is a model, not a measurement. These are its "
                "inputs, so you can put your own numbers in rather than argue with ours.",
    },
    {
        "id": "views",
        "label": "What the console shows by default",
        "help": "Defaults for someone opening the console for the first time. "
                "Anyone can still switch, per session, from the header.",
    },
]

SETTINGS: list[dict[str, Any]] = [
    # ── Detection sensitivity ────────────────────────────────────────────────
    {
        "key": "detection.brute_force_attempts",
        "group": "detection",
        "label": "Failed logins before we call it an attack",
        "help": "Counted per source against one host.",
        "type": "int",
        "default": 3,
        "min": 1,
        "max": 50,
        "step": 1,
        "unit": "attempts",
        "affects": "Raising this hides slow password guessing; lowering it flags "
                   "users who simply mistyped.",
        "demo": 10,
    },
    {
        "key": "detection.exfil_ratio",
        "group": "detection",
        "label": "Outbound-to-inbound size ratio that counts as data leaving",
        "help": "A normal request sends a little and receives a lot. Data theft is the "
                "other way round.",
        "type": "float",
        "default": 10.0,
        "min": 1.5,
        "max": 200.0,
        "step": 0.5,
        "unit": ": 1",
        "affects": "Raising this misses slow, low-volume theft; lowering it flags "
                   "ordinary uploads and backups — on the demo records, tightening it turns a "
                   "customer downloading their own statement into a critical exfiltration alert.",
        "demo": 5.0,
    },
    {
        "key": "detection.suspicious_score_floor",
        "group": "detection",
        "label": "How unusual something must be before it is worth showing",
        "help": "Anything below this is recorded but treated as normal activity.",
        "type": "float",
        "default": 0.60,
        "min": 0.05,
        "max": 0.95,
        "step": 0.05,
        "unit": "score",
        "affects": "Lowering this fills the queue with routine traffic; raising it "
                   "quietly drops weak signals.",
        "demo": 0.30,
    },
    {
        "key": "detection.confidence_cap",
        "group": "detection",
        "label": "Highest confidence we will ever claim",
        "help": "A ceiling, so no verdict is ever presented as certain.",
        "type": "float",
        "default": 0.95,
        # Floored at the malicious threshold rather than at an arbitrary 0.50.
        # The cross-field rule below refuses anything under it, so a lower floor
        # advertised a range that was two-thirds unreachable and made this
        # setting's own "try" button fail every time.
        "min": MALICIOUS_VERDICT_THRESHOLD,
        "max": 1.0,
        "step": 0.01,
        "unit": "confidence",
        "affects": "Only the confidence figure shown to analysts. It never changes a "
                   "severity.",
        "demo": 0.99,
    },
    {
        "key": "detection.campaign_min_stage",
        "group": "detection",
        "label": "How far an attacker must get before we assume they own the host",
        "help": "Alerts chain into one attack when a victim becomes the next source. "
                "This is the point at which we believe that happened.",
        "type": "choice",
        "default": "3",
        "options": KILL_CHAIN_STAGES,
        "affects": "Setting this to Reconnaissance makes an authorised vulnerability "
                   "scan chain onto everything it touched, producing one enormous false campaign.",
        "demo": "1",
    },

    # ── Severity policy ─────────────────────────────────────────────────────
    *[
        {
            "key": f"severity.{threat}",
            "group": "severity",
            "label": label,
            "type": "choice",
            "default": default,
            "options": [(s, s.capitalize()) for s in SEVERITIES],
            "affects": "Where these alerts sort in the queue, and whether they reach "
                       "the threshold for telling a regulator.",
            "demo": demo,
        }
        for threat, label, default, demo in [
            ("port_scan", "Someone scanning our exposed services", "medium", "low"),
            ("web_attack", "An attack against a public web application", "high", "critical"),
            ("brute_force_attempt", "Repeated password guessing", "high", "medium"),
            ("credential_abuse", "Valid credentials used abnormally", "high", "critical"),
            ("beaconing", "A machine calling out to attacker infrastructure", "high", "critical"),
            ("lateral_movement", "An attacker moving between our systems", "critical", "high"),
            ("data_exfiltration", "Data leaving the network", "critical", "high"),
        ]
    ],

    # ── Regulatory reporting ────────────────────────────────────────────────
    {
        "key": "reporting.regimes",
        "group": "reporting",
        "label": "Regimes this institution is subject to",
        "help": "Clocks are only raised for the ones ticked.",
        "type": "multi",
        "default": [r[0] for r in REGIME_OPTIONS],
        "options": REGIME_OPTIONS,
        "min_selected": 1,
        "affects": "Which countdowns appear on Reporting, and which deadline is called "
                   "the soonest one.",
        "demo": ["cert_in"],
    },
    {
        "key": "reporting.min_severity",
        "group": "reporting",
        "label": "Least serious incident that can start a reporting clock",
        "help": "Below this, an incident is handled but no regulator is notified.",
        "type": "choice",
        "default": "high",
        "options": [(s, s.capitalize()) for s in SEVERITIES],
        "affects": "Loosening this starts legal clocks for routine events. Tightening "
                   "it risks missing a notification you owed.",
        "demo": "critical",
    },
    {
        "key": "reporting.require_foothold",
        "group": "reporting",
        "label": "Only report once an attacker actually got in",
        "help": "On: scanning and blocked attempts never raise a clock, however severe "
                "they looked.",
        "type": "bool",
        "default": True,
        "affects": "Turning this off starts a four-hour DORA clock for every port scan.",
        "demo": False,
    },

    # ── Response autonomy ───────────────────────────────────────────────────
    {
        "key": "response.automatic_actions",
        "group": "response",
        "label": "Actions the system may take without asking",
        "help": "Everything else is recommended and held for approval.",
        "type": "multi",
        # Blocking an external address at the edge is the narrowest and most
        # reversible action in the playbook, so it ships permitted. The two that
        # do not are the ones that take a person or a machine offline.
        "default": ["enrich", "notify", "monitor", "block_ip"],
        "options": RESPONSE_ACTIONS,
        "min_selected": 0,
        "affects": "The share of containment shown as automatic, and how many actions "
                   "wait in the approvals queue. Withholding a category never overrides the "
                   "blast-radius gate — that one is about damage, not permission.",
        "demo": ["enrich", "notify", "monitor"],
    },
    {
        "key": "response.gate_above_hosts",
        "group": "response",
        "label": "Ask a person if an action would affect more than this many hosts",
        "help": "A blast-radius limit. It applies even to actions ticked above.",
        "type": "int",
        "default": 1,
        "min": 1,
        "max": 500,
        "step": 1,
        "unit": "hosts",
        "affects": "Raising this lets one automated action touch a large part of the "
                   "estate unattended.",
        "demo": 25,
    },

    # ── The savings model ───────────────────────────────────────────────────
    {
        "key": "model.manual_minutes_per_alert",
        "group": "model",
        "label": "Minutes an analyst spends triaging one alert by hand",
        "help": "Pulling context from the SIEM, checking the source against threat "
                "intel, deciding severity, writing it up. Our default of 15 is deliberately "
                "conservative — published SOC research puts manual investigation well above "
                "it — so the saving we claim is a floor. Substitute your own measured figure.",
        "type": "float",
        "default": 15.0,
        "min": 1.0,
        "max": 240.0,
        "step": 1.0,
        "unit": "minutes",
        "affects": "The hours-saved figure on the dashboard.",
        "demo": 25.0,
    },
    {
        "key": "model.review_minutes_per_incident",
        "group": "model",
        "label": "Minutes to review one grouped investigation",
        "help": "Reading the generated analysis, agreeing or disagreeing, deciding the "
                "response. The system removes the gathering, not the judgement.",
        "type": "float",
        "default": 4.0,
        "min": 0.5,
        "max": 120.0,
        "step": 0.5,
        "unit": "minutes",
        "affects": "The hours-saved figure. Must stay below the manual figure above, "
                   "or the system is claiming to cost time.",
        "demo": 6.0,
    },

    # ── Console defaults ────────────────────────────────────────────────────
    {
        "key": "views.default_detail",
        "group": "views",
        "label": "Level of detail the console opens at",
        "type": "choice",
        "default": "overview",
        "options": [
            ("overview", "Plain language — no identifiers or jargon"),
            ("analyst", "Full detail — technique IDs, control IDs, raw records"),
        ],
        "affects": "What a first-time visitor sees. Anyone can still switch from the "
                   "header.",
        "demo": "analyst",
    },
    {
        "key": "views.queue_grouping",
        "group": "views",
        "label": "How the main queue is arranged",
        "help": "Grouped shows one row per attack; flat shows every individual alert.",
        "type": "choice",
        "default": "investigations",
        "options": [
            ("investigations", "One row per attack, alerts folded inside"),
            ("alerts", "Every alert, most serious first"),
        ],
        "affects": "Whether the queue length matches the 'things to look at' count "
                   "above it, or lists every alert that fed into them.",
        "demo": "alerts",
    },
    {
        "key": "views.default_severity_filter",
        "group": "views",
        "label": "Severity filter the queue starts on",
        "type": "choice",
        "default": "all",
        "options": [("all", "Everything")] + [(s, s.capitalize()) for s in SEVERITIES[:3]],
        "affects": "Only the starting position of the filter buttons.",
        "demo": "critical",
    },
]

SETTINGS_BY_KEY: dict[str, dict[str, Any]] = {s["key"]: s for s in SETTINGS}
DEFAULTS: dict[str, Any] = {s["key"]: s["default"] for s in SETTINGS}


# ─────────────────────────────────────────────────────────────────────────────
# Reading
# ─────────────────────────────────────────────────────────────────────────────

# (mtime_ns, size) of the file the cache was built from. Statting is cheap;
# re-parsing per call is not, and this is read many times per pipeline run.
_cache_stamp: tuple[int, int] | None = None
_cache: dict[str, Any] = {}


def _parse_stored() -> dict[str, Any]:
    """
    The stored file as a dict, or an empty one for anything unusable.

    Absence, unreadable permissions, invalid UTF-8, malformed JSON and
    well-formed JSON of the wrong shape all land in the same place: defaults.
    A configuration file is the last thing that should be able to stop a SOC
    pipeline from running.
    """
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # ValueError covers both json.JSONDecodeError and UnicodeDecodeError.
        return {}
    return raw if isinstance(raw, dict) else {}


def _read_overrides() -> dict[str, Any]:
    """Load the override file, tolerating absence and corruption."""
    global _cache_stamp, _cache

    try:
        stat = CONFIG_PATH.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        # No file yet: pure defaults. Cache that too, so the common case does
        # not stat-and-fail on every read.
        if _cache_stamp is not None:
            _cache_stamp, _cache = None, {}
        return _cache

    if stamp == _cache_stamp:
        return _cache

    stored = _parse_stored().get("values")
    if not isinstance(stored, dict):
        # Covers a missing key and every wrong shape: null, a list, a string.
        # The dict comprehension below used to sit outside the guard, so
        # `{"values": null}` raised AttributeError out of every layer at once.
        stored = {}

    # Drop anything the current schema no longer knows about, so a stale file
    # cannot resurrect a removed setting — and anything whose stored type no
    # longer matches its declared one. The file is the feature's own storage
    # format, so someone will edit it by hand; validate() must not be bypassable
    # just because the value arrived from disk instead of over HTTP.
    _cache = {}
    for key, value in stored.items():
        if key not in SETTINGS_BY_KEY:
            continue
        coerced, problem = _coerce(SETTINGS_BY_KEY[key], value)
        if problem is None:
            _cache[key] = coerced
    _cache_stamp = stamp
    return _cache


# An in-process override layer, used to answer "what would this change do?"
# without writing anything. Deliberately a plain module global rather than a
# context var: the settings screen previews one candidate at a time, and making
# it look thread-safe when the pipeline underneath keeps module-level state
# would be a false promise. The endpoint that uses it says so.
_preview: dict[str, Any] | None = None


@contextlib.contextmanager
def previewing(patch: dict[str, Any]):
    """Apply a candidate configuration for the duration of the block only."""
    global _preview
    previous = _preview
    _preview = dict(patch)
    try:
        yield
    finally:
        _preview = previous


def invalidate() -> None:
    """Drop the cache. For tests, and after an in-process write."""
    global _cache_stamp, _cache
    _cache_stamp, _cache = None, {}


def get(key: str) -> Any:
    """
    Current value for one setting.

    Called at the point of use rather than at import, so a saved change takes
    effect on the next pipeline run without a restart.
    """
    if key not in SETTINGS_BY_KEY:
        raise KeyError(f"unknown setting: {key}")
    if _preview is not None and key in _preview:
        return _preview[key]
    return _read_overrides().get(key, DEFAULTS[key])


def get_int(key: str) -> int:
    return int(get(key))


def get_float(key: str) -> float:
    return float(get(key))


def get_bool(key: str) -> bool:
    return bool(get(key))


def get_list(key: str) -> list[str]:
    value = get(key)
    return list(value) if isinstance(value, (list, tuple)) else []


def values() -> dict[str, Any]:
    """Every setting resolved to its current value."""
    overrides = _read_overrides()
    resolved = {key: overrides.get(key, default) for key, default in DEFAULTS.items()}
    if _preview:
        resolved.update({k: v for k, v in _preview.items() if k in DEFAULTS})
    return resolved


def stored_values() -> dict[str, Any]:
    """
    Resolved values ignoring any preview in flight.

    Validation and saving must both reason about what is actually persisted:
    deciding a cross-field rule, or a from-value for the audit trail, against a
    candidate configuration would be quietly wrong.
    """
    overrides = _read_overrides()
    return {key: overrides.get(key, default) for key, default in DEFAULTS.items()}


def modified_keys() -> list[str]:
    """Which settings differ from their shipped default, in schema order."""
    current = stored_values()
    return [k for k in DEFAULTS if current[k] != DEFAULTS[k]]


# ─────────────────────────────────────────────────────────────────────────────
# Validation
#
# Returns every problem rather than the first, because an operator fixing a form
# should see all of it at once. Field errors are keyed by setting so the console
# can render them against the control that caused them.
# ─────────────────────────────────────────────────────────────────────────────

def _coerce(spec: dict[str, Any], raw: Any) -> tuple[Any, str | None]:
    kind = spec["type"]
    label = spec["label"]

    if kind in ("int", "float"):
        if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
            return None, f"{label} must be a number."
        try:
            value = int(raw) if kind == "int" else float(raw)
        except (TypeError, ValueError, OverflowError):
            return None, f"“{raw}” is not a number."
        # NaN compares False to every bound, so it slips through a range check
        # unnoticed — and json.dumps then writes a bare `NaN`, which is not JSON
        # and which poisons every later read. Infinity fails the bounds honestly;
        # NaN has to be named.
        if not math.isfinite(value):
            return None, f"{label} must be an ordinary number."
        low, high = spec["min"], spec["max"]
        if value < low or value > high:
            unit = spec.get("unit", "")
            return None, f"Must be between {low} and {high}{(' ' + unit) if unit else ''}."
        return value, None

    if kind == "bool":
        if isinstance(raw, bool):
            return raw, None
        if isinstance(raw, str) and raw.lower() in ("true", "false"):
            return raw.lower() == "true", None
        return None, f"{label} must be on or off."

    if kind == "choice":
        allowed = [o[0] for o in spec["options"]]
        if raw not in allowed:
            return None, f"Must be one of: {', '.join(allowed)}."
        return raw, None

    if kind == "multi":
        if not isinstance(raw, (list, tuple)):
            return None, f"{label} must be a list of choices."
        allowed = [o[0] for o in spec["options"]]
        unknown = [str(v) for v in raw if v not in allowed]
        if unknown:
            return None, f"Not a valid choice: {', '.join(unknown)}."
        chosen = list(dict.fromkeys(raw))  # de-duplicate, keep order
        floor = spec.get("min_selected", 0)
        if len(chosen) < floor:
            return None, f"Choose at least {floor}."
        return chosen, None

    return None, f"{label} has an unsupported type."


def validate(patch: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """
    Check a proposed change.

    Returns (cleaned, errors). `cleaned` holds only well-formed entries, but
    callers must not write it unless `errors` is empty — a partial save is the
    failure mode this exists to prevent.
    """
    cleaned: dict[str, Any] = {}
    errors: dict[str, str] = {}

    if not isinstance(patch, dict):
        return {}, {"_": "Expected an object of setting keys to values."}

    for key, raw in patch.items():
        spec = SETTINGS_BY_KEY.get(key)
        if spec is None:
            errors[key] = "Not a setting this system has."
            continue
        value, problem = _coerce(spec, raw)
        if problem:
            errors[key] = problem
        else:
            cleaned[key] = value

    # ── Cross-field rules ────────────────────────────────────────────────────
    # Checked against the merged result, not the patch, so changing one half of
    # a pair is caught against the stored other half.
    merged = {**stored_values(), **cleaned}

    # The confidence ceiling sits above the threshold at which a verdict becomes
    # "malicious" (0.85 in detection_fusion). Set it lower and no incident can
    # ever be called malicious again — a total behaviour change with no error
    # message anywhere. Refusing it is the whole reason this cross-check exists.
    cap = merged["detection.confidence_cap"]
    if isinstance(cap, (int, float)) and cap < MALICIOUS_VERDICT_THRESHOLD:
        errors["detection.confidence_cap"] = (
            f"Must stay above {MALICIOUS_VERDICT_THRESHOLD:g}. Below that, no incident "
            "could ever be labelled malicious, because the verdict needs a confidence "
            "the ceiling would no longer allow."
        )

    manual = merged["model.manual_minutes_per_alert"]
    review = merged["model.review_minutes_per_incident"]
    if isinstance(manual, (int, float)) and isinstance(review, (int, float)) and review >= manual:
        message = (
            f"Reviewing an investigation ({review:g} min) cannot cost as much as "
            f"triaging every alert by hand ({manual:g} min) — that would make the "
            "time-saved figure zero or negative."
        )
        target = (
            "model.review_minutes_per_incident"
            if "model.review_minutes_per_incident" in cleaned
            else "model.manual_minutes_per_alert"
        )
        errors[target] = message

    return cleaned, errors


# ─────────────────────────────────────────────────────────────────────────────
# Writing
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(UTC).isoformat()


def _append_audit(changes: list[dict[str, Any]], actor: str) -> None:
    """Record what changed. Best effort: a failed audit write must not fail the save."""
    if not changes:
        return
    try:
        history = json.loads(AUDIT_PATH.read_text(encoding="utf-8")) if AUDIT_PATH.exists() else []
        if not isinstance(history, list):
            history = []
    except (OSError, json.JSONDecodeError):
        history = []

    history.insert(0, {"at": _now(), "actor": str(actor)[:120], "changes": changes})
    with contextlib.suppress(OSError, ValueError):
        # allow_nan=False so a non-finite value can never be written as the bare
        # `NaN` token, which json.loads accepts on the way back in and which
        # therefore survives every attempt to clear it.
        AUDIT_PATH.write_text(
            json.dumps(history[:AUDIT_LIMIT], indent=2, allow_nan=False), encoding="utf-8"
        )


def save(patch: dict[str, Any], actor: str = "console") -> dict[str, Any]:
    """
    Apply a validated patch.

    Raises ValueError carrying the field errors if the patch does not validate —
    callers turn that into a 4xx rather than writing anything.
    """
    cleaned, errors = validate(patch)
    if errors:
        raise ValueError(json.dumps(errors))

    # Read past any preview in flight. A save that measured "what changed"
    # against a candidate configuration would record the wrong before-value, and
    # could drop a genuine change as a no-op.
    before = stored_values()
    overrides = dict(_read_overrides())

    changes = []
    for key, value in cleaned.items():
        if before[key] == value:
            continue
        changes.append({"key": key, "label": SETTINGS_BY_KEY[key]["label"],
                        "from": before[key], "to": value})
        # A value returned to its default is removed rather than stored, so the
        # file stays a record of genuine differences.
        if value == DEFAULTS[key]:
            overrides.pop(key, None)
        else:
            overrides[key] = value

    payload = {
        "version": 1,
        "updated_at": _now(),
        "updated_by": actor,
        "values": overrides,
    }
    # Written via a temporary file and replaced atomically: a crash mid-write must
    # not leave a half-parsed config that silently reverts to defaults. The temp
    # name carries the pid, because a single shared name means two concurrent
    # saves race on the same file and the atomicity is lost exactly when it is
    # needed.
    tmp = CONFIG_PATH.with_name(f"{CONFIG_PATH.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(payload, indent=2, allow_nan=False), encoding="utf-8")
        os.replace(tmp, CONFIG_PATH)
    except (OSError, ValueError):
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    invalidate()

    _append_audit(changes, actor)
    return {"changes": changes, "values": values(), "modified": modified_keys()}


def reset(actor: str = "console") -> dict[str, Any]:
    """Return every setting to its shipped default."""
    before = stored_values()
    changes = [
        {"key": k, "label": SETTINGS_BY_KEY[k]["label"], "from": before[k], "to": DEFAULTS[k]}
        for k in modified_keys()
    ]
    with contextlib.suppress(FileNotFoundError):
        CONFIG_PATH.unlink()
    invalidate()
    _append_audit(changes, f"{actor} (reset to defaults)")
    return {"changes": changes, "values": values(), "modified": []}


# ─────────────────────────────────────────────────────────────────────────────
# Describing, for the console
# ─────────────────────────────────────────────────────────────────────────────

def audit() -> list[dict[str, Any]]:
    """
    The change history, or nothing if it is unusable.

    Deliberately defensive: status() embeds this, so a single unreadable entry
    here used to 500 the whole settings console — including the reset endpoint
    that was the way out. The recovery path must never depend on the audit log
    being well-formed.
    """
    try:
        history = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(history, list):
        return []
    return [
        entry for entry in history
        if isinstance(entry, dict) and isinstance(entry.get("changes"), list)
    ]


def _display_path() -> str:
    try:
        return str(CONFIG_PATH.relative_to(ROOT))
    except ValueError:
        return str(CONFIG_PATH)


def status() -> dict[str, Any]:
    """
    Everything the settings screen needs in one response: the schema, the current
    values, what differs from default, when it last changed, and whether the
    stored file is readable at all.
    """
    stored_ok = True
    updated_at = None
    updated_by = None
    if CONFIG_PATH.exists():
        raw = _parse_stored()
        if raw and isinstance(raw.get("values", {}), dict):
            updated_at = raw.get("updated_at")
            updated_by = raw.get("updated_by")
        else:
            # A file that exists but yields nothing usable. Reported rather than
            # hidden, so the console can warn instead of quietly showing defaults
            # as though they were chosen.
            stored_ok = False

    modified = modified_keys()
    return {
        "groups": GROUPS,
        # `options` is emitted as [value, label] pairs so the console renders the
        # wording from here rather than keeping its own copy in sync.
        "settings": [
            {
                "key": s["key"],
                "group": s["group"],
                "label": s["label"],
                "help": s.get("help"),
                "type": s["type"],
                "default": s["default"],
                "min": s.get("min"),
                "max": s.get("max"),
                "step": s.get("step"),
                "unit": s.get("unit"),
                "options": [list(o) for o in s.get("options", [])] or None,
                "min_selected": s.get("min_selected"),
                "affects": s["affects"],
                "demo": s.get("demo"),
            }
            for s in SETTINGS
        ],
        "values": values(),
        "defaults": DEFAULTS,
        "modified": modified,
        "is_default": not modified,
        "updated_at": updated_at,
        "updated_by": updated_by,
        "stored_file_readable": stored_ok,
        # Shown as a repo-relative path where it is one, absolute where it is not.
        # relative_to() raises rather than falling back, and a status endpoint that
        # throws because the file lives somewhere unexpected is worse than useless.
        "path": _display_path(),
        "audit": audit()[:8],
    }
