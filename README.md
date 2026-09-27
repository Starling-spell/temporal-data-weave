# TemporalDataWeave

TemporalDataWeave is a source-bound temporal state primitive for timelines, immutable state packets and safe historical freezing.

State creation binds an HTTPS source and expected SHA-256 commitment. During `append_state`, GenLayer independently fetches both current and parent documents, recomputes full-response hashes, extracts explicitly stated entity names and ISO dates, and requires exact equality of the complete report across validators. A same-entity, later-date transition produces `APPEND`; contradictory dates produce `REJECTED`. Missing, mismatched or ambiguous evidence produces `INCONCLUSIVE`. Only `APPEND` advances the timeline version and head.

Workflow: `create_timeline → append_state → append_state(parent) → freeze_timeline`.

This contract does not claim that external data is true. It proves that committed bytes were independently fetched and that the stated temporal relationship passed exact validator recomputation. Each timeline binds one object; stale parent heads cannot advance it. See `LIVE_PROOFS.md` for finalized StudioNet transactions.
