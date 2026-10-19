"""Saved project rules and recovery of projects created before project switching."""

from __future__ import annotations

from contextlib import suppress

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from opti.configs import kinds, revisions
from opti.configs.runtime import ConfigSnapshot
from opti.core.config import ProjectRules
from opti.db.models import Project
from opti.settings import Settings


def rules_text(rules: ProjectRules) -> str:
    return kinds.from_data("rules", kinds.to_data("rules", rules))


async def save(s: AsyncSession, rules: ProjectRules) -> None:
    values = {"authorization_ref": rules.authorization_ref, "rules_yaml": rules_text(rules)}
    await s.execute(
        insert(Project)
        .values(id=rules.project, name=rules.project, **values)
        .on_conflict_do_update(index_elements=[Project.id], set_=values)
    )


async def catalog(
    s: AsyncSession, settings: Settings, snapshot: ConfigSnapshot
) -> dict[str, tuple[str, ProjectRules | None]]:
    """History is newest first; never invent another project's rules by changing its ID."""
    found: dict[str, tuple[str, ProjectRules | None]] = {}

    def add(text: str, *, aliases: bool = False) -> None:
        try:
            model = kinds.parse("rules", text, allow_aliases=aliases)
        except kinds.ConfigInvalid:
            return
        if found.get(model.project, ("", None))[1] is None:
            name = found.get(model.project, (model.project, None))[0]
            found[model.project] = (name, model)

    for project in await s.scalars(select(Project).order_by(Project.id)):
        found[project.id] = (project.name, None)
        if project.rules_yaml:
            # A mismatched snapshot must not make a different project selectable.
            try:
                model = kinds.parse("rules", project.rules_yaml)
            except kinds.ConfigInvalid:
                continue
            if model.project == project.id:
                found[project.id] = (project.name, model)
    for revision in await revisions.history(s, "rules"):
        add(revision.content)
    add(rules_text(snapshot.rules))
    with suppress(OSError):
        add(kinds.read_file("rules", settings), aliases=True)
    return found
