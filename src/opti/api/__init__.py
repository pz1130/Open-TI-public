"""研判接口（设计文档 15）：/api/v1，Cookie 会话 + RBAC，写操作全部审计。"""

from importlib.metadata import PackageNotFoundError, version

try:
    VERSION = version("opti")
except PackageNotFoundError:
    VERSION = "0.0.0"
