"""Drop bare SHA-256 digests of discovered secrets (replaced by keyed HMAC fingerprints).

Revision ID: 0034
Revises: 0033

The raw secret is never stored, so old digests cannot be converted to HMAC; they are
removed. Affected findings keep rule/file/line but lose their fingerprint until rescanned.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0034"
down_revision: str | None = "0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STRIP = """
UPDATE finding SET match = jsonb_set(
    match, '{scan,secrets}',
    (SELECT coalesce(jsonb_agg(s - 'sha256'), '[]'::jsonb)
       FROM jsonb_array_elements(match->'scan'->'secrets') AS s)
)
WHERE jsonb_typeof(match->'scan'->'secrets') = 'array'
  AND jsonb_path_exists(match, '$.scan.secrets[*].sha256')
"""


def upgrade() -> None:
    op.get_bind().execute(sa.text(_STRIP))


def downgrade() -> None:
    pass  # 删除的裸哈希不可恢复，也不应恢复
