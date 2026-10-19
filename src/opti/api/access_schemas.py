"""Public account and authorization models; credentials are input-only."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class UserOut(BaseModel):
    id: int
    username: str
    display_name: str
    auth_source: str
    active: bool
    roles: list[str]
    idp_roles: list[str]
    permission_sets: list[str]
    permissions: list[str]
    must_change_password: bool
    locked_until: datetime | None
    created_at: datetime
    last_login_at: datetime | None
    version: int


class UserPage(BaseModel):
    items: list[UserOut]
    total: int


class UserCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=r"^[a-z0-9._-]{2,64}$")
    display_name: str = Field(default="", max_length=100)
    password: SecretStr = Field(min_length=12, max_length=1000)
    roles: list[str] = Field(default_factory=list, max_length=100)
    permission_sets: list[str] = Field(default_factory=list, max_length=100)


class UserUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str = Field(max_length=100)
    active: bool
    roles: list[str] = Field(max_length=100)
    permission_sets: list[str] = Field(max_length=100)
    base_version: int = Field(ge=1)


class UserPasswordIn(BaseModel):
    password: SecretStr = Field(min_length=12, max_length=1000)
    base_version: int = Field(ge=1)


class PasswordChangeIn(BaseModel):
    current_password: SecretStr = Field(min_length=1, max_length=1000)
    new_password: SecretStr = Field(min_length=12, max_length=1000)


class PermissionInfo(BaseModel):
    id: str
    group: str
    description: str


class PermissionSetOut(BaseModel):
    name: str
    display_name: str
    description: str
    permissions: list[str]
    builtin: bool
    version: int


class AccessRoleOut(PermissionSetOut):
    permission_sets: list[str]


class AccessCatalog(BaseModel):
    permissions: list[PermissionInfo]
    roles: list[AccessRoleOut]
    permission_sets: list[PermissionSetOut]


class PermissionSetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    display_name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)
    permissions: list[str] = Field(max_length=100)
    base_version: int = Field(default=0, ge=0)


class AccessRoleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    display_name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)
    permission_sets: list[str] = Field(max_length=100)
    base_version: int = Field(default=0, ge=0)
