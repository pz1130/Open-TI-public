"""Administrator-controlled global project switching."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from opti.api.config_store import store
from opti.api.deps import CurrentUser, Principal, get_deps, require
from opti.api.rbac import Perm
from opti.configs import projects, revisions

router = APIRouter(tags=["projects"])
Admin = Annotated[Principal, Depends(require(Perm.PROJECTS_WRITE))]


class ActiveProject(BaseModel):
    project_id: str
    rules_version: int


class ProjectSummary(BaseModel):
    project_id: str
    name: str
    active: bool
    available: bool


class ProjectList(BaseModel):
    items: list[ProjectSummary]
    total: int
    active_project: str
    rules_version: int


class ActivateProject(BaseModel):
    project_id: str = Field(min_length=1)
    base_version: int = Field(ge=0)


@router.get("/projects/current", response_model=ActiveProject)
async def current(request: Request, user: CurrentUser) -> ActiveProject:
    deps = get_deps(request)
    # Use the same pinned snapshot as the rest of this request.
    return ActiveProject(
        project_id=deps.rules.project, rules_version=deps.snapshot.version("rules")
    )


@router.get("/admin/projects", response_model=ProjectList)
async def listing(
    request: Request,
    user: Admin,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> ProjectList:
    deps = get_deps(request)
    async with deps.sessions() as s:
        entries = await projects.catalog(s, deps.settings, deps.snapshot)
        head = await revisions.latest(s, "rules")
    items = [
        ProjectSummary(
            project_id=pid, name=name, active=pid == deps.rules.project, available=rules is not None
        )
        for pid, (name, rules) in sorted(entries.items())
    ]
    start = (page - 1) * page_size
    return ProjectList(
        items=items[start : start + page_size],
        total=len(items),
        active_project=deps.rules.project,
        rules_version=head.version if head else 0,
    )


@router.post("/admin/projects/activate", response_model=ActiveProject)
async def activate(request: Request, user: Admin, body: ActivateProject) -> ActiveProject:
    deps = get_deps(request)
    async with deps.sessions() as s:
        entries = await projects.catalog(s, deps.settings, deps.snapshot)
    if body.project_id not in entries:
        raise HTTPException(404, "项目不存在")
    rules = entries[body.project_id][1]
    if rules is None:
        raise HTTPException(409, "项目缺少可恢复的完整规则，请先由管理员导入该项目的规则配置")
    changed = await store(
        request,
        user,
        "rules",
        projects.rules_text(rules),
        rules,
        base_version=body.base_version,
        confirm=True,
        note=f"Activate project {body.project_id}",
        restored_from=None,
    )
    return ActiveProject(project_id=rules.project, rules_version=body.base_version + int(changed))
