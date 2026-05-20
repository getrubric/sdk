"""Tests for ``rubric._scrub``.

Mirrors the Node SDK's ``scrub-secrets.test.mjs`` test cases. Each pattern
gets a positive case (must redact) and at least one negative case (must NOT
touch). Also covers ``scrub_deep`` recursion + cycle safety, plus the
``err_message`` / ``err_code`` helpers.
"""

from __future__ import annotations

import pytest

from rubric._scrub import err_code, err_message, scrub_deep, scrub_secrets


# ---- JWT --------------------------------------------------------------------


def test_jwt_three_part_dotted_token_collapses_to_single_redaction() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    out = scrub_secrets(f"refresh failed (500): {jwt}")
    assert "<redacted:jwt>" in out
    assert jwt not in out
    # Single token, not three (no `<redacted:blob>` from the catch-all
    # eating the three dot-separated chunks).
    assert out.count("<redacted:jwt>") == 1


def test_jwt_multiple_in_one_string_each_get_redacted() -> None:
    j1 = "eyJabc.eyJdef.sig1"
    j2 = "eyJghi.eyJjkl.sig2"
    out = scrub_secrets(f"first {j1} and second {j2}")
    assert j1 not in out
    assert j2 not in out
    assert out.count("<redacted:jwt>") == 2


def test_jwt_negative_plain_text_without_dot_triplet_is_untouched() -> None:
    s = "hello world, no secret here"
    assert scrub_secrets(s) == s


# ---- Bearer headers ---------------------------------------------------------


def test_bearer_preserves_literal_prefix_and_redacts_payload() -> None:
    s = "Authorization: Bearer abcdef1234567890abcdef"
    out = scrub_secrets(s)
    assert "Bearer <redacted>" in out
    assert "abcdef1234567890abcdef" not in out


def test_bearer_short_tokens_below_16_chars_not_matched_by_bearer_rule() -> None:
    # `short` is 5 chars — below both the Bearer floor (16) and the
    # base64ish floor (24), so it must pass through verbatim.
    s = "Bearer short"
    out = scrub_secrets(s)
    assert "Bearer" in out
    assert "short" in out


# ---- 64-char hex (daemon token shape) --------------------------------------


def test_hex64_exact_64_lowercase_hex_string_is_redacted() -> None:
    tok = "a" * 64
    out = scrub_secrets(f"daemon token: {tok}")
    assert "<redacted:hex64>" in out
    assert tok not in out


def test_hex64_63_char_run_falls_through_to_base64ish_catchall() -> None:
    tok = "a" * 63
    out = scrub_secrets(f"x: {tok}")
    # Below the 64 threshold for hex64, but ≥24 → catch-all fires.
    assert tok not in out
    assert "<redacted:blob>" in out


def test_hex64_content_hash_shaped_run_inside_larger_string() -> None:
    h = "deadbeef" * 8  # 64 chars
    out = scrub_secrets(f"bundle contentHash={h} verified")
    assert h not in out
    assert "<redacted:hex64>" in out


# ---- base64-ish blob -------------------------------------------------------


def test_base64ish_at_least_24_chars_is_redacted() -> None:
    blob = "A" * 30
    out = scrub_secrets(f"opaque: {blob}")
    assert "<redacted:blob>" in out


def test_base64ish_23_char_run_is_below_floor_and_passes_through() -> None:
    blob = "A" * 23
    out = scrub_secrets(f"opaque: {blob}")
    assert blob in out


# ---- Provider-shape secrets ------------------------------------------------


def test_provider_openai_sk_key_redacted() -> None:
    k = "sk-" + "A" * 40
    out = scrub_secrets(f"key: {k}")
    assert k not in out
    assert "<redacted:secret>" in out


def test_provider_github_ghp_key_redacted() -> None:
    k = "ghp_" + "B" * 30
    out = scrub_secrets(f"token: {k}")
    assert k not in out
    assert "<redacted:secret>" in out


def test_provider_slack_xoxb_and_xoxp_redacted() -> None:
    k1 = "xoxb-" + "1" * 40
    k2 = "xoxp-" + "2" * 40
    assert k1 not in scrub_secrets(k1)
    assert k2 not in scrub_secrets(k2)


def test_provider_aws_akia_key_redacted() -> None:
    k = "AKIA" + "A" * 16
    out = scrub_secrets(f"aws: {k}")
    assert k not in out
    assert "<redacted:secret>" in out


def test_provider_rubric_enr_enrollment_token_redacted() -> None:
    k = "enr_abc123_xyz-ABCDEF"
    out = scrub_secrets(f"enrollment: {k}")
    assert k not in out
    assert "<redacted:secret>" in out


def test_provider_negative_sk_with_too_few_suffix_chars_passes_through() -> None:
    # `sk-Aa` has 2 chars after the prefix — below the ≥20 floor. Pass-through.
    s = "sk-Aa is short"
    out = scrub_secrets(s)
    assert "sk-Aa" in out


# ---- Postgres URL with embedded credentials --------------------------------


def test_postgres_url_embedded_creds_redacted_scheme_host_preserved() -> None:
    url = "postgres://alice:s3cret@db.internal:5432/prod"
    out = scrub_secrets(f"could not connect: {url}")
    assert "postgres://<redacted>@" in out
    assert "alice:s3cret" not in out
    # Host/path preserved.
    assert "db.internal" in out


def test_postgresql_scheme_also_handled() -> None:
    url = "postgresql://bob:hunter2@host/db"
    out = scrub_secrets(url)
    assert "postgresql://<redacted>@" in out
    assert "bob:hunter2" not in out


def test_postgres_url_negative_no_creds_means_no_postgres_specific_redaction() -> None:
    # No `user:pw@` shape and the host is short enough to skip base64ish.
    s = "postgres://db.internal/prod"
    out = scrub_secrets(s)
    assert "postgres://db.internal/prod" in out


# ---- Idempotency / safety --------------------------------------------------


def test_empty_string_is_returned_unchanged() -> None:
    assert scrub_secrets("") == ""


def test_running_scrub_secrets_twice_on_its_own_output_is_stable() -> None:
    s = "Bearer abcdef1234567890abcdef and " + "a" * 64
    once = scrub_secrets(s)
    twice = scrub_secrets(once)
    assert once == twice


def test_does_not_crash_on_weird_unicode_and_preserves_emoji() -> None:
    s = "token=🔑 eyJabc.eyJdef.sig 🦀"
    out = scrub_secrets(s)
    assert "<redacted:jwt>" in out
    assert "🔑" in out
    assert "🦀" in out


# ---- scrub_deep ------------------------------------------------------------


def test_scrub_deep_walks_nested_dicts_lists_and_strings() -> None:
    jwt = "eyJabc.eyJdef.sig1"
    payload = {
        "auth": f"Bearer {'a' * 32}",
        "nested": {
            "items": [
                "ok",
                f"key={jwt}",
                {"db": "postgres://u:p@h/d"},
            ],
        },
        "passthrough": 42,
    }
    out = scrub_deep(payload)
    assert isinstance(out, dict)
    assert out["auth"] == "Bearer <redacted>"
    assert out["nested"]["items"][0] == "ok"
    assert "<redacted:jwt>" in out["nested"]["items"][1]
    assert jwt not in out["nested"]["items"][1]
    assert out["nested"]["items"][2]["db"] == "postgres://<redacted>@h/d"
    # Non-string leaves are returned unchanged.
    assert out["passthrough"] == 42


def test_scrub_deep_returns_original_for_unsupported_scalar_types() -> None:
    assert scrub_deep(42) == 42
    assert scrub_deep(3.14) == 3.14
    assert scrub_deep(None) is None
    assert scrub_deep(True) is True


def test_scrub_deep_walks_tuples() -> None:
    out = scrub_deep(("ok", "AKIA" + "B" * 16))
    assert isinstance(out, tuple)
    assert out[0] == "ok"
    assert out[1] == "<redacted:secret>"


def test_scrub_deep_handles_self_referential_dict_without_infinite_loop() -> None:
    d: dict[str, object] = {"name": "loopy"}
    d["self"] = d
    out = scrub_deep(d)
    assert isinstance(out, dict)
    assert out["name"] == "loopy"
    assert out["self"] == "<redacted:cycle>"


def test_scrub_deep_handles_self_referential_list_without_infinite_loop() -> None:
    lst: list[object] = ["ok"]
    lst.append(lst)
    out = scrub_deep(lst)
    assert isinstance(out, list)
    assert out[0] == "ok"
    assert out[1] == "<redacted:cycle>"


def test_scrub_deep_sibling_repeats_of_same_object_are_not_falsely_cycled() -> None:
    # The same dict referenced twice as siblings (not as an ancestor) should
    # NOT be flagged as a cycle — the seen-set is popped on the way back up.
    shared = {"k": "ok"}
    out = scrub_deep({"a": shared, "b": shared})
    assert out["a"] == {"k": "ok"}
    assert out["b"] == {"k": "ok"}


def test_scrub_deep_empty_containers() -> None:
    assert scrub_deep({}) == {}
    assert scrub_deep([]) == []
    assert scrub_deep(()) == ()


# ---- err_message / err_code ------------------------------------------------


def test_err_message_returns_str_of_exception() -> None:
    err = ValueError("boom")
    assert err_message(err) == "boom"


def test_err_message_works_on_bare_exception() -> None:
    err = Exception()
    # str(Exception()) is "" — must not raise.
    assert err_message(err) == ""


def test_err_code_returns_string_code_when_present() -> None:
    class CodedError(Exception):
        code = "ENOENT"

    assert err_code(CodedError()) == "ENOENT"


def test_err_code_returns_none_when_code_is_missing() -> None:
    assert err_code(ValueError("no code here")) is None


def test_err_code_returns_none_when_code_is_not_a_string() -> None:
    class NumericCode(Exception):
        code = 2  # OSError-like integer errno

    assert err_code(NumericCode()) is None


@pytest.mark.parametrize(
    "raw,must_contain,must_not_contain",
    [
        ("Bearer " + "x" * 32, "Bearer <redacted>", "x" * 32),
        ("sk-" + "A" * 30, "<redacted:secret>", "sk-" + "A" * 30),
        ("a" * 64, "<redacted:hex64>", "a" * 64),
    ],
)
def test_parametrized_redaction_smoke(
    raw: str, must_contain: str, must_not_contain: str
) -> None:
    out = scrub_secrets(raw)
    assert must_contain in out
    assert must_not_contain not in out
