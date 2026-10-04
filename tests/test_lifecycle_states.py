"""Pure tests for the incident lifecycle rules (PRD section 22) and decision vocabulary (PRD section 21)."""
import pytest

from app.lifecycle import states as st
from app.lifecycle.states import LifecycleError


def test_all_prd_states_exist_and_transitions_are_closed_over_them():
    assert set(st.STATES) == {"DETECTED", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "NEEDS_INVESTIGATION", "RESPONSE_RECOMMENDED", "ACTION_TAKEN", "RESOLVED"}
    assert set(st.TRANSITIONS) == set(st.STATES)
    for src, targets in st.TRANSITIONS.items():
        assert targets <= set(st.STATES) and src not in targets
    assert st.CLOSED_STATES == {"RESOLVED", "FALSE_POSITIVE"}


def test_prd_happy_path_is_allowed_step_by_step():
    path = ["DETECTED", "INVESTIGATING", "CONFIRMED", "RESPONSE_RECOMMENDED", "ACTION_TAKEN", "RESOLVED"]
    for a, b in zip(path, path[1:]):
        st.check_transition(a, b)


@pytest.mark.parametrize("src,dst", [("DETECTED", "RESOLVED"), ("DETECTED", "ACTION_TAKEN"), ("DETECTED", "RESPONSE_RECOMMENDED"), ("INVESTIGATING", "ACTION_TAKEN"),
                                     ("CONFIRMED", "ACTION_TAKEN"), ("ACTION_TAKEN", "CONFIRMED"), ("RESOLVED", "CONFIRMED"), ("RESOLVED", "ACTION_TAKEN"),
                                     ("FALSE_POSITIVE", "ACTION_TAKEN"), ("RESPONSE_RECOMMENDED", "CONFIRMED")])
def test_skipping_or_reversing_steps_is_refused_with_a_controlled_error(src, dst):
    with pytest.raises(LifecycleError) as e:
        st.check_transition(src, dst)
    assert e.value.code == "invalid_transition" and e.value.status_code == 409 and e.value.extra["allowed"] == st.allowed_next(src)


def test_resolved_can_only_be_reopened_and_missing_status_means_detected():
    assert st.allowed_next("RESOLVED") == ["INVESTIGATING"]
    assert st.allowed_next(None) == st.allowed_next("DETECTED")


def test_decision_vocabulary_matches_prd_feedback_options():
    assert st.DECISIONS == ("CONFIRMED", "FALSE_POSITIVE", "NEEDS_INVESTIGATION")
    for raw, want in (("True Positive", "CONFIRMED"), ("true_positive", "CONFIRMED"), ("confirmed", "CONFIRMED"), ("FALSE-POSITIVE", "FALSE_POSITIVE"),
                      ("false positive", "FALSE_POSITIVE"), ("Needs Investigation", "NEEDS_INVESTIGATION"), ("investigate_further", "NEEDS_INVESTIGATION")):
        assert st.normalise_decision(raw) == want, raw
    for bad in ("", None, "malicious", "resolved", "accept"):
        with pytest.raises(LifecycleError) as e:
            st.normalise_decision(bad)
        assert e.value.status_code == 422


def test_recommendation_decisions_are_accept_reject_further_investigation():
    assert st.normalise_recommendation_decision("accept") == "accepted"
    assert st.normalise_recommendation_decision("Reject") == "rejected"
    assert st.normalise_recommendation_decision("further-investigation") == "needs_investigation"
    with pytest.raises(LifecycleError):
        st.normalise_recommendation_decision("execute")


def test_state_names_are_normalised_and_unknown_ones_rejected():
    assert st.normalise_state("response recommended") == "RESPONSE_RECOMMENDED" and st.normalise_state("false-positive") == "FALSE_POSITIVE"
    with pytest.raises(LifecycleError):
        st.normalise_state("DELETED")


def test_comment_cleaning():
    assert st.clean_comment("  ok\x00\x07 fine\nline2 ") == "ok fine\nline2"
    assert st.clean_comment("   ") is None and st.clean_comment(None) is None
    with pytest.raises(LifecycleError) as e:
        st.clean_comment("x" * (st.MAX_COMMENT_CHARS + 1))
    assert e.value.code == "comment_too_long"


def test_alert_status_follows_lifecycle():
    assert st.alert_status_for("CONFIRMED", "open") == "acknowledged"
    assert st.alert_status_for("FALSE_POSITIVE", "acknowledged") == "closed"
    assert st.alert_status_for("RESOLVED", "open") == "closed"
    assert st.alert_status_for("INVESTIGATING", "closed") == "open"            # reopening
    assert st.alert_status_for("INVESTIGATING", "acknowledged") == "acknowledged"
    assert st.alert_status_for("INVESTIGATING", None) is None


def test_public_config_has_no_secrets_and_explains_action_taken():
    c = st.public_config()
    assert c["states"] == list(st.STATES) and c["transitions"]["RESOLVED"] == ["INVESTIGATING"]
    assert any("executes nothing" in n for n in c["notes"])
