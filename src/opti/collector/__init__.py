"""境外采集节点（设计文档 3.4）：拉取任务、运行连接器与富化器、回传结果。无状态，不持有数据库凭据。"""

from importlib.metadata import PackageNotFoundError, version

try:
    VERSION = version("opti")
except PackageNotFoundError:  # 未安装为包（例如直接从源码运行）
    VERSION = "0.0.0"
