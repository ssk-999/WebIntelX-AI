import numpy as np
import pytest

from app.ml.preprocessing import FEATURE_NAMES, FEATURES, Baseline, build_matrix, session_features
from app.pipeline.sessionization import sessionize
from tests.anomaly_helpers import attacker_events, baseline_events


def _ctx_for(events, key):
    return sessionize(events)[key]


def test_features_for_a_known_session():
    ctx = _ctx_for(attacker_events(failures=100, span_s=40), "sess-attack")
    f = session_features(ctx)
    assert set(f) == set(FEATURE_NAMES)
    assert f["login_failures"] == 100 and f["distinct_failed_users"] == 30 and f["sensitive_accesses"] == 5
    assert f["error_ratio"] == pytest.approx(100 / 105)          # 100 failures carry status 401 -> error statuses
    assert f["median_page_gap_s"] is None and f["interaction_per_page"] is None    # no page views -> undefined, not 0


def test_matrix_shape_and_nan_for_undefined():
    sessions = sessionize(baseline_events(10) + attacker_events())
    X = build_matrix(list(sessions.values()))
    assert X.shape == (11, len(FEATURES))
    j = FEATURE_NAMES.index("median_page_gap_s")
    atk = list(sessions).index("sess-attack")
    assert np.isnan(X[atk, j]) and not np.isnan(X[0, j])
    assert build_matrix([]).shape == (0, len(FEATURES))


def test_baseline_is_robust_to_outliers_and_imputes_median():
    sessions = sessionize(baseline_events(60) + attacker_events())
    X = build_matrix(list(sessions.values()))
    b = Baseline().fit(X)
    j = FEATURE_NAMES.index("login_failures")
    assert b.median[j] == 0.0                                    # one attacker does not move the median
    assert b.scale[j] >= 1.0                                     # min-scale floor: near-constant feature stays finite
    Xi = b.impute(X)
    assert not np.isnan(Xi).any()
    k = FEATURE_NAMES.index("median_page_gap_s")
    atk = list(sessions).index("sess-attack")
    assert Xi[atk, k] == b.median[k]                             # undefined -> median, i.e. no evidence of deviation


def test_deviations_only_count_the_unusual_direction():
    sessions = sessionize(baseline_events(60) + attacker_events())
    X = build_matrix(list(sessions.values()))
    b = Baseline().fit(X)
    Z = b.deviations(X)
    assert (Z >= 0).all()
    atk = list(sessions).index("sess-attack")
    assert Z[atk, FEATURE_NAMES.index("login_failures")] > 50
    # a session with page gaps HIGHER than normal is not unusual for a 'low'-direction feature
    slow = X.copy()
    k = FEATURE_NAMES.index("median_page_gap_s")
    slow[0, k] = b.median[k] * 10
    assert b.deviations(slow)[0, k] == 0.0
    # ... while an unusually LOW gap is
    fast = X.copy()
    fast[0, k] = 0.1
    assert b.deviations(fast)[0, k] > 0.0


def test_unfitted_and_bad_input_are_rejected():
    with pytest.raises(RuntimeError):
        Baseline().deviations(np.zeros((1, len(FEATURES))))
    with pytest.raises(RuntimeError):
        Baseline().impute(np.zeros((1, len(FEATURES))))
    with pytest.raises(ValueError):
        Baseline().fit(np.zeros((0, len(FEATURES))))
    with pytest.raises(ValueError):
        Baseline().fit(np.zeros((3, 2)))


def test_all_nan_column_does_not_crash():
    X = np.zeros((5, len(FEATURES)))
    X[:, 0] = np.nan
    b = Baseline().fit(X)
    assert b.median[0] == 0.0 and np.isfinite(b.scale).all() and (b.scale > 0).all()
