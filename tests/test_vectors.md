# Test vectors

- Exact source bytes with an explicit entity and ISO date produce `APPEND`.
- A second same-entity document with a later date and current head as parent advances the version.
- An equal/earlier date or changed entity produces `REJECTED`.
- Wrong hash, unavailable source, incomplete body or ambiguous dates produce `INCONCLUSIVE`.
- Reused state IDs and frozen timelines are rejected before nondeterministic execution.
