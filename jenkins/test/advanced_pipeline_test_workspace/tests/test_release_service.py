from src.services.release_service import create_release_candidate


def test_create_release_candidate():
    rc = create_release_candidate("1.0.0", "abc123")
    assert rc.version == "1.0.0"
    assert rc.commit_id == "abc123"
