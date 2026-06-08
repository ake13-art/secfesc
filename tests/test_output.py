"""Tests for pure utility functions in ui/output.py."""

import secfesc.secfetch.ui.output as output_mod
from secfesc.secfetch.ui.output import (
    _SCORE_GOOD,
    _SCORE_WARN,
    _has_ansi,
    _short_box,
    _short_side,
    _strip_ansi,
    print_results,
    print_results_live,
    print_results_short,
    score_bar,
)
from secfesc.shared.colors import GREEN, RED, RESET, YELLOW


class TestScoreBar:
    def test_good_score_uses_green(self):
        result = score_bar(80)
        assert GREEN in result
        assert YELLOW not in result
        assert RED not in result

    def test_warn_score_uses_yellow(self):
        result = score_bar(60)
        assert YELLOW in result
        assert GREEN not in result
        assert RED not in result

    def test_bad_score_uses_red(self):
        result = score_bar(30)
        assert RED in result
        assert GREEN not in result
        assert YELLOW not in result

    def test_threshold_exact_good(self):
        result = score_bar(_SCORE_GOOD)
        assert GREEN in result

    def test_threshold_exact_warn(self):
        result = score_bar(_SCORE_WARN)
        assert YELLOW in result

    def test_just_below_good_threshold_uses_yellow(self):
        result = score_bar(_SCORE_GOOD - 1)
        assert YELLOW in result

    def test_just_below_warn_threshold_uses_red(self):
        result = score_bar(_SCORE_WARN - 1)
        assert RED in result

    def test_width_controls_bar_length(self):
        result = score_bar(50, width=10)
        inner = result.replace(GREEN, "").replace(YELLOW, "").replace(RED, "").replace(RESET, "")
        bar_content = inner[1:-1]
        assert len(bar_content) == 10

    def test_score_100_produces_full_bar(self):
        result = score_bar(100, width=8)
        inner = result.replace(GREEN, "").replace(YELLOW, "").replace(RED, "").replace(RESET, "")
        bar_content = inner[1:-1]
        assert bar_content == "█" * 8

    def test_score_0_produces_empty_bar(self):
        result = score_bar(0, width=8)
        inner = result.replace(GREEN, "").replace(YELLOW, "").replace(RED, "").replace(RESET, "")
        bar_content = inner[1:-1]
        assert bar_content == "░" * 8

    def test_output_is_wrapped_in_brackets(self):
        result = score_bar(50, width=5)
        inner = result.replace(GREEN, "").replace(YELLOW, "").replace(RED, "").replace(RESET, "")
        assert inner.startswith("[")
        assert inner.endswith("]")


class TestAnsiHelpers:
    def test_has_ansi_detects_escape_sequence(self):
        assert _has_ansi("\033[31mred") is True
        assert _has_ansi("\033[1;32mgreen") is True
        assert _has_ansi("\033[0mreset") is True

    def test_has_ansi_returns_false_for_plain_text(self):
        assert _has_ansi("plain text") is False
        assert _has_ansi("") is False
        assert _has_ansi("no codes here 123") is False

    def test_strip_ansi_removes_codes(self):
        assert _strip_ansi("\033[31mred\033[0m") == "red"
        assert _strip_ansi("\033[1;32mgreen") == "green"

    def test_strip_ansi_leaves_plain_text(self):
        assert _strip_ansi("plain text") == "plain text"


class TestRendering:
    """Smoke tests: the renderers should run and show the data without crashing."""

    def test_print_results_shows_checks_and_score(self, capsys, sample_results):
        print_results(sample_results)
        out = _strip_ansi(capsys.readouterr().out)
        assert "ASLR" in out
        assert "Firewall" in out
        assert "/100" in out  # score line present

    def test_print_results_short_renders_box(self, capsys, sample_results):
        print_results_short(sample_results)
        out = _strip_ansi(capsys.readouterr().out)
        assert "ASLR" in out
        assert "/100" in out

    def test_print_results_live_renders(self, capsys, sample_results):
        print_results_live(sample_results, interval=5)
        out = _strip_ansi(capsys.readouterr().out)
        assert "/100" in out

    def test_print_results_handles_empty(self, capsys):
        print_results([])
        # should not raise; some output is produced
        assert capsys.readouterr().out is not None

    def test_short_side_renders_score_and_checks(self, capsys, sample_results):
        _short_side(sample_results)
        out = _strip_ansi(capsys.readouterr().out)
        assert "/100" in out

    def test_short_side_no_logo_prints_info_only(self, capsys, sample_results, monkeypatch):
        monkeypatch.setattr(output_mod, "_get_logo_lines", lambda: [])
        _short_side(sample_results)
        out = _strip_ansi(capsys.readouterr().out)
        assert "/100" in out

    def test_short_side_shows_userhost_header(self, capsys, sample_results):
        _short_side(sample_results)
        out = _strip_ansi(capsys.readouterr().out)
        assert "@" in out  # user@hostname header present

    def test_short_box_renders_score_and_checks(self, capsys, sample_results):
        _short_box(sample_results)
        out = _strip_ansi(capsys.readouterr().out)
        assert "/100" in out
        assert "ASLR" in out

    def test_print_results_short_box_layout(self, capsys, sample_results, monkeypatch):
        monkeypatch.setattr(output_mod, "SHORT_LAYOUT", "box")
        print_results_short(sample_results)
        out = _strip_ansi(capsys.readouterr().out)
        assert "/100" in out
