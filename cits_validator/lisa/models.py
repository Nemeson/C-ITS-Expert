from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CLASS_VEHICLE = "vehicle"
CLASS_PEDESTRIAN = "pedestrian"
CLASS_BICYCLE = "bicycle"
CLASS_TRANSIT = "transit"
CLASS_UNKNOWN = "unknown"


@dataclass
class LisaSignalGroup:
    obj_nr: int
    bezeichnung: str = ""
    name: str = ""
    classification: str = CLASS_UNKNOWN
    aspects: list[str] = field(default_factory=list)
    is_pedestrian: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "obj_nr": self.obj_nr,
            "bezeichnung": self.bezeichnung,
            "name": self.name,
            "classification": self.classification,
            "aspects": self.aspects,
            "is_pedestrian": self.is_pedestrian,
        }


@dataclass
class LisaSupplyCatalog:
    intersection_name: str | None = None
    groups: dict[int, LisaSignalGroup] = field(default_factory=dict)

    def by_obj_nr(self, obj_nr: int) -> LisaSignalGroup | None:
        return self.groups.get(obj_nr)

    def __len__(self) -> int:
        return len(self.groups)

    def to_dict(self) -> dict[str, Any]:
        return {
            "intersection_name": self.intersection_name,
            "groups": {k: v.to_dict() for k, v in self.groups.items()},
        }
