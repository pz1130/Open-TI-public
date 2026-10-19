"""Analyst-uploaded screenshots: uploader and original file hash.

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("evidence", sa.Column("uploaded_by", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        "fk_evidence_uploaded_by_app_user", "evidence", "app_user", ["uploaded_by"], ["id"]
    )
    op.add_column("evidence", sa.Column("original_sha256", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("evidence", "original_sha256")
    op.drop_constraint("fk_evidence_uploaded_by_app_user", "evidence", type_="foreignkey")
    op.drop_column("evidence", "uploaded_by")
