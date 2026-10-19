from opti.cli import DB_COMMANDS, _parser


def test_campaign_recompute_command_is_registered() -> None:
    assert "campaign-recompute" in DB_COMMANDS
    assert _parser().parse_args(["campaign-recompute"]).cmd == "campaign-recompute"
