from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class ReleaseCandidate:
    version: str
    commit_id: str
    created_at: str


def create_release_candidate(version: str, commit_id: str) -> ReleaseCandidate:
    return ReleaseCandidate(
        version=version,
        commit_id=commit_id,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
