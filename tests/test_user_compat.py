"""user_compat — metered/guest fallback accessor."""
import user_compat


def test_canonical_metered_true():
    assert user_compat.is_metered({'metered': True}) is True


def test_canonical_metered_false():
    assert user_compat.is_metered({'metered': False}) is False


def test_legacy_guest_true_when_metered_absent():
    assert user_compat.is_metered({'guest': True}) is True


def test_legacy_guest_false_when_metered_absent():
    assert user_compat.is_metered({'guest': False}) is False


def test_canonical_metered_overrides_legacy_guest():
    """If both keys present, `metered` is authoritative."""
    assert user_compat.is_metered({'metered': True, 'guest': False}) is True
    assert user_compat.is_metered({'metered': False, 'guest': True}) is False


def test_missing_both_returns_false():
    assert user_compat.is_metered({}) is False


def test_non_dict_input_returns_false():
    assert user_compat.is_metered(None) is False
    assert user_compat.is_metered('string') is False
    assert user_compat.is_metered(0) is False


def test_truthy_values_coerce_to_bool():
    assert user_compat.is_metered({'metered': 1}) is True
    assert user_compat.is_metered({'metered': 'yes'}) is True
    assert user_compat.is_metered({'guest': 1}) is True
