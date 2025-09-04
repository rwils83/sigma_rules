#!/usr/bin/env python3
"""
sigma_rule_wizard.py — OOP, extensible Sigma rule builder.

- Generates UUID v4 for `id`
- Presets for Windows Security, Sysmon, Apache access (custom allowed)
- Add multiple selections (sel_*), each with one or more field matchers
- Condition defaults to OR of all selections (you can override)
- Basic validation for IDs, status/level enums, selections, and condition refs
- Writes spec-compliant YAML to ./out_sigma_oop/<slug>-<shortuuid>.yml

Requires: pyyaml
  pip install pyyaml
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Dict, List, Union, Optional
import re
import uuid
import yaml


# ---------- Enums ----------

class Status(str, Enum):
    experimental = "experimental"
    test = "test"
    stable = "stable"
    deprecated = "deprecated"


class Level(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# ---------- Core models ----------

@dataclass
class LogSource:
    product: str
    service: str
    category: Optional[str] = None

    @staticmethod
    def windows_security(category: str = "account_change") -> "LogSource":
        return LogSource(product="windows", service="security", category=category)

    @staticmethod
    def sysmon(category: str = "process_creation") -> "LogSource":
        return LogSource(product="windows", service="sysmon", category=category)

    @staticmethod
    def apache_access() -> "LogSource":
        return LogSource(product="apache", service="access", category="webserver")


@dataclass
class Selection:
    """A named selection (e.g., sel_methods) containing field matchers."""
    name: str
    matchers: Dict[str, Union[str, List[str]]] = field(default_factory=dict)

    def add(self, field_key: str, values: Union[str, List[str]]) -> "Selection":
        """field_key may include Sigma ops, e.g., 'request|contains'."""
        if isinstance(values, list) and len(values) == 1:
            values = values[0]
        self.matchers[field_key] = values
        return self

    def to_dict(self) -> Dict[str, Dict[str, Union[str, List[str]]]]:
        return {self.name: self.matchers}


@dataclass
class SigmaRule:
    title: str
    id: str
    status: Status
    description: str
    logsource: LogSource
    detection_selections: List[Selection]
    condition: str
    level: Level
    references: List[str] = field(default_factory=list)
    author: str = "Unknown"
    date: str = field(default_factory=lambda: str(date.today()))
    tags: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)

    UUID_RE = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    )

    def validate(self) -> None:
        if not self.title.strip():
            raise ValueError("title is required")
        if not self.UUID_RE.match(self.id):
            raise ValueError("id must be a UUID v4")
        if not isinstance(self.status, Status):
            raise ValueError("status must be a Status enum value")
        if not isinstance(self.level, Level):
            raise ValueError("level must be a Level enum value")
        if not isinstance(self.logsource, LogSource):
            raise ValueError("logsource must be a LogSource")
        if not self.detection_selections:
            raise ValueError("at least one selection is required")

        # sanity: selections referenced in condition must exist
        sel_names = {s.name for s in self.detection_selections}
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", self.condition)  # bare identifiers
        unknown = [t for t in tokens if t.startswith("sel_") and t not in sel_names]
        if unknown:
            raise ValueError(f"condition references unknown selections: {unknown}")

    def to_yaml_dict(self) -> Dict:
        self.validate()
        data = {
            "title": self.title,
            "id": self.id,
            "status": self.status.value,
            "description": self.description,
            "references": self.references,
            "author": self.author,
            "date": self.date,
            "tags": self.tags,
            "logsource": {k: v for k, v in asdict(self.logsource).items() if v},
            "detection": {},
            "fields": self.fields,
            "falsepositives": self.falsepositives,
            "level": self.level.value,
        }
        for sel in self.detection_selections:
            data["detection"].update(sel.to_dict())
        data["detection"]["condition"] = self.condition
        return data

    def to_yaml(self) -> str:
        return yaml.dump(self.to_yaml_dict(), sort_keys=False, allow_unicode=True)

    def save(self, path: Union[str, Path]) -> Path:
        out = Path(path)
        out.write_text(self.to_yaml(), encoding="utf-8")
        return out


# ---------- Helpers / Builder ----------

def slugify(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", s.strip()).strip("-").lower() or "rule"


class RuleBuilder:
    """
    Interactive wizard that builds SigmaRule with multiple selections.
    """

    def __init__(self):
        self._title: str = ""
        self._id: str = str(uuid.uuid4())
        self._status: Status = Status.experimental
        self._description: str = ""
        self._references: List[str] = []
        self._author: str = "Ryan Wilson"
        self._date: str = str(date.today())
        self._tags: List[str] = []
        self._logsource: Optional[LogSource] = None
        self._selections: List[Selection] = []
        self._condition: Optional[str] = None
        self._fields: List[str] = []
        self._falsepositives: List[str] = []
        self._level: Level = Level.medium

    # ----- small I/O helpers -----

    @staticmethod
    def _prompt(msg: str, default: Optional[str] = None, required: bool = False) -> str:
        while True:
            raw = input(f"{msg}{' ['+default+']' if default else ''}: ").strip()
            if not raw and default is not None:
                raw = default
            if required and not raw:
                print("  -> required.")
                continue
            return raw

    @staticmethod
    def _prompt_list(msg: str) -> List[str]:
        s = input(f"{msg} (comma-separated; blank=none): ").strip()
        return [x.strip() for x in s.split(",") if x.strip()] if s else []

    # ----- fluent setters (optional programmatic use) -----

    def title(self, t: str) -> "RuleBuilder":
        self._title = t.strip()
        return self

    def description(self, d: str) -> "RuleBuilder":
        self._description = d.strip()
        return self

    def author(self, a: str) -> "RuleBuilder":
        self._author = a.strip()
        return self

    def status(self, s: Status) -> "RuleBuilder":
        self._status = s
        return self

    def level(self, l: Level) -> "RuleBuilder":
        self._level = l
        return self

    def tags(self, tags: List[str]) -> "RuleBuilder":
        self._tags = [t.strip() for t in tags if t.strip()]
        return self

    def references(self, refs: List[str]) -> "RuleBuilder":
        self._references = [r.strip() for r in refs if r.strip()]
        return self

    def fields(self, fields: List[str]) -> "RuleBuilder":
        self._fields = [f.strip() for f in fields if f.strip()]
        return self

    def falsepositives(self, fps: List[str]) -> "RuleBuilder":
        self._falsepositives = [f.strip() for f in fps if f.strip()]
        return self

    def logsource(self, logsource: LogSource) -> "RuleBuilder":
        self._logsource = logsource
        return self

    def add_selection(self, name: str, matchers: Dict[str, Union[str, List[str]]]) -> "RuleBuilder":
        sel = Selection(name=name)
        for k, v in matchers.items():
            sel.add(k, v)
        self._selections.append(sel)
        return self

    def condition(self, expr: str) -> "RuleBuilder":
        self._condition = expr.strip()
        return self

    # ----- interactive wizard -----

    def interactive(self) -> "RuleBuilder":
        print("\n=== Sigma OOP Wizard ===")
        self._title = self._prompt("Title", required=True)
        self._description = self._prompt("Description", required=True)
        self._author = self._prompt("Author", default=self._author) or self._author

        # status + level
        while True:
            s = self._prompt("Status [experimental|test|stable|deprecated]", default=self._status.value)
            if s in {e.value for e in Status}:
                self._status = Status(s); break
            print("  -> invalid status.")
        while True:
            l = self._prompt("Level [low|medium|high|critical]", default=self._level.value)
            if l in {e.value for e in Level}:
                self._level = Level(l); break
            print("  -> invalid level.")

        self._references = self._prompt_list("References")
        self._tags = self._prompt_list("Tags")
        self._fields = self._prompt_list("Fields to show")
        self._falsepositives = self._prompt_list("False positives")

        # logsource presets
        print("\nLogSource presets:\n 1) Windows Security\n 2) Windows Sysmon\n 3) Apache access\n 4) Custom")
        choice = self._prompt("Choose 1-4", default="1")
        if choice == "1":
            cat = self._prompt("Windows category (e.g., password_change, account_change, process_creation)",
                               default="account_change")
            self._logsource = LogSource.windows_security(category=cat)
        elif choice == "2":
            cat = self._prompt("Sysmon category (e.g., process_creation, file_access, network_connection)",
                               default="process_creation")
            self._logsource = LogSource.sysmon(category=cat)
        elif choice == "3":
            self._logsource = LogSource.apache_access()
        else:
            prod = self._prompt("logsource.product (e.g., windows, apache)", required=True)
            serv = self._prompt("logsource.service (e.g., security, sysmon, access)", required=True)
            cat = self._prompt("logsource.category (optional)")
            self._logsource = LogSource(product=prod, service=serv, category=cat or None)

        # selections loop (fixed UX)
        print("\nAdd selections (e.g., sel_eventid, sel_methods, sel_strings).")
        print("For each selection, add one or more field matchers (e.g., 'EventID' or 'request|contains').")
        idx = 1
        added_any = False

        # simple field key validator: starts with letter/_ ; allow dots and |operator
        key_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*(\|[a-z_]+)?$")

        def default_field_key() -> str:
            ls = self._logsource
            if ls and ls.product == "windows":
                return "EventID"
            if ls and ls.product in ("apache", "nginx"):
                return "request|contains"
            return "EventID"

        while True:
            yn = self._prompt("Add a selection? (y/n)", default=("y" if not added_any else "n")).lower()
            if yn in ("n", "no", ""):
                break

            name = self._prompt("  Selection name", default=f"sel_{idx}")
            matchers: Dict[str, Union[str, List[str]]] = {}

            while True:
                fk = self._prompt("    Field key (e.g., EventID or request|contains; blank=done)")
                if not fk:
                    break

                if fk.isdigit():
                    # user likely typed a value at field prompt
                    guessed = default_field_key()
                    print(f"      (Looks like a value; assuming field '{guessed}')")
                    values = [fk] + self._prompt_list("    Additional values")
                    fk = guessed
                else:
                    if not key_re.match(fk):
                        print("      -> Invalid field key. Try 'EventID' or 'request|contains'.")
                        continue
                    values = self._prompt_list("    Values")

                if not values:
                    print("      -> at least one value required; try again.")
                    continue

                matchers[fk] = values if len(values) > 1 else values[0]

            if not matchers:
                print("  -> empty selection skipped.")
            else:
                self.add_selection(name, matchers)
                print(f"  ✓ Added selection '{name}' with {len(matchers)} matcher(s).")
                added_any = True
                idx += 1

        if not self._selections:
            raise ValueError("No selections were added; rule requires at least one selection.")

        # default condition is OR of all selections
        default_cond = " or ".join(s.name for s in self._selections)
        self._condition = self._prompt(f"Condition (default: '{default_cond}')", default=default_cond) or default_cond
        return self

    # build the SigmaRule
    def build(self) -> SigmaRule:
        if not self._logsource:
            raise ValueError("logsource not set")
        rule = SigmaRule(
            title=self._title,
            id=str(uuid.uuid4()),
            status=self._status,
            description=self._description,
            logsource=self._logsource,
            detection_selections=self._selections,
            condition=self._condition or (self._selections[0].name if self._selections else "sel_1"),
            level=self._level,
            references=self._references,
            author=self._author,
            date=str(date.today()),
            tags=self._tags,
            fields=self._fields,
            falsepositives=self._falsepositives,
        )
        rule.validate()
        return rule


# ---------- CLI ----------

def main():
    builder = RuleBuilder().interactive()
    rule = builder.build()

    short_id = rule.id.split("-")[0]
    fname = f"{slugify(rule.title)}-{short_id}.yml"
    outdir = Path.cwd() / "rules"
    outdir.mkdir(exist_ok=True)
    path = outdir / fname
    rule.save(path)

    print(f"\n✅ Saved: {path}")
    print("Next steps:")
    print(f"  sigma check   \"{path}\"")
    print(f"  sigma convert -t es-qs -p windows \"{path}\"   # if Windows rule")
    print(f"  sigma convert -t es-qs \"{path}\"              # if Apache rule")


if __name__ == "__main__":
    main()

