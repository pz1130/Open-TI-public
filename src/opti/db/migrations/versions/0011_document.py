"""Document storage and full-text indexes (S4-A).

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EMPTY_ARRAY = sa.text("'{}'::text[]")


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.create_table(
        "document",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("url_normalized", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), server_default="", nullable=False),
        sa.Column("snippet", sa.Text(), server_default="", nullable=False),
        sa.Column("contexts", pg.ARRAY(sa.Text()), server_default=EMPTY_ARRAY, nullable=False),
        sa.Column("search_text", sa.Text(), server_default="", nullable=False),
        sa.Column("language", sa.Text(), nullable=True),
        sa.Column("source_name", sa.Text(), server_default="", nullable=False),
        sa.Column("connectors", pg.ARRAY(sa.Text()), server_default=EMPTY_ARRAY, nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("content_sha256", sa.Text(), nullable=False),
        sa.Column("simhash", sa.BigInteger(), nullable=False),
        sa.Column("cluster_id", sa.BigInteger(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_document"),
        sa.UniqueConstraint("url_normalized", name="uq_document_url_normalized"),
    )
    op.create_index("ix_document_cluster_id", "document", ["cluster_id"])
    op.create_index("ix_document_first_seen", "document", ["first_seen"])
    op.create_index("ix_document_last_seen", "document", ["last_seen"])
    op.create_index("ix_document_content_sha256", "document", ["content_sha256"])
    op.execute(
        "CREATE INDEX ix_document_search_tsv ON document USING gin (to_tsvector('simple', search_text))"
    )
    op.execute(
        "CREATE INDEX ix_document_search_trgm ON document USING gin (search_text gin_trgm_ops)"
    )


def downgrade() -> None:
    op.drop_table("document")
