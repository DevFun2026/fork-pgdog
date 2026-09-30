from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any
import tomllib


_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class ModelError(ValueError):
    """Raised when the canonical project model is invalid."""


@dataclass(frozen=True)
class Component:
    id: str
    name: str
    kind: str
    responsibility: str
    trust_boundary: str


@dataclass(frozen=True)
class Relationship:
    id: str
    source: str
    target: str
    label: str


@dataclass(frozen=True)
class DataFlow:
    id: str
    source: str
    target: str
    data_categories: tuple[str, ...]
    trust_boundary: str


@dataclass(frozen=True)
class Environment:
    id: str
    name: str
    description: str


@dataclass(frozen=True)
class ProjectModel:
    title: str
    purpose: str
    data_categories: tuple[str, ...]
    sensitive_categories: tuple[str, ...]
    components: tuple[Component, ...]
    relationships: tuple[Relationship, ...]
    data_flows: tuple[DataFlow, ...]
    environments: tuple[Environment, ...]


def _read(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ModelError(f"cannot load {path.name}: {exc}") from exc


def _required_text(item: dict[str, Any], field: str, kind: str) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ModelError(f"{kind}.{field} must be a non-empty string")
    return value.strip()


def _identifier(item: dict[str, Any], kind: str) -> str:
    value = _required_text(item, "id", kind)
    if not _ID.fullmatch(value):
        raise ModelError(f"invalid {kind} id: {value}")
    return value


def _unique(items: list[Any], kind: str) -> None:
    seen: set[str] = set()
    for item in items:
        if item.id in seen:
            raise ModelError(f"duplicate {kind} id: {item.id}")
        seen.add(item.id)


def _rows(data: dict[str, Any], field: str) -> list[dict[str, Any]]:
    value = data.get(field, [])
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ModelError(f"{field} must be an array of tables")
    return value


def _string_list(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ModelError(f"{field} must be an array of non-empty strings")
    return tuple(sorted(set(value)))


def load_project_model(path: str | Path) -> ProjectModel:
    root = Path(path)
    component_data = _read(root / "components.toml")
    relationship_data = _read(root / "relationships.toml")
    flow_data = _read(root / "data-flows.toml")
    environment_data = _read(root / "environments.toml")

    title = _required_text(component_data, "title", "model")
    purpose = _required_text(component_data, "purpose", "model")
    categories = _string_list(component_data.get("data_categories", []), "data_categories")
    sensitive = _string_list(
        component_data.get("sensitive_categories", []), "sensitive_categories"
    )
    for category in sensitive:
        if category not in categories:
            raise ModelError(f"undeclared sensitive data category: {category}")

    components = [
        Component(
            id=_identifier(row, "component"),
            name=_required_text(row, "name", "component"),
            kind=_required_text(row, "kind", "component"),
            responsibility=_required_text(row, "responsibility", "component"),
            trust_boundary=_required_text(row, "trust_boundary", "component"),
        )
        for row in _rows(component_data, "components")
    ]
    _unique(components, "component")
    component_ids = {item.id for item in components}

    relationships = [
        Relationship(
            id=_identifier(row, "relationship"),
            source=_required_text(row, "source", "relationship"),
            target=_required_text(row, "target", "relationship"),
            label=_required_text(row, "label", "relationship"),
        )
        for row in _rows(relationship_data, "relationships")
    ]
    _unique(relationships, "relationship")

    flows = [
        DataFlow(
            id=_identifier(row, "data flow"),
            source=_required_text(row, "source", "data flow"),
            target=_required_text(row, "target", "data flow"),
            data_categories=_string_list(
                row.get("data_categories", []), "data_flow.data_categories"
            ),
            trust_boundary=_required_text(row, "trust_boundary", "data flow"),
        )
        for row in _rows(flow_data, "data_flows")
    ]
    _unique(flows, "data flow")

    for item in (*relationships, *flows):
        for endpoint in (item.source, item.target):
            if endpoint not in component_ids:
                raise ModelError(f"unknown component: {endpoint}")
    for flow in flows:
        for category in flow.data_categories:
            if category not in categories:
                raise ModelError(f"undeclared data category: {category}")

    environments = [
        Environment(
            id=_identifier(row, "environment"),
            name=_required_text(row, "name", "environment"),
            description=_required_text(row, "description", "environment"),
        )
        for row in _rows(environment_data, "environments")
    ]
    _unique(environments, "environment")

    return ProjectModel(
        title=title,
        purpose=purpose,
        data_categories=categories,
        sensitive_categories=sensitive,
        components=tuple(sorted(components, key=lambda item: item.id)),
        relationships=tuple(sorted(relationships, key=lambda item: item.id)),
        data_flows=tuple(sorted(flows, key=lambda item: item.id)),
        environments=tuple(sorted(environments, key=lambda item: item.id)),
    )
