# Proactive Action Card V1

Status: `IMPLEMENTED / S6-E_LIVE_GATE_PASS`

## 1. Boundary

`data-steward.proactive-action-card/v1` is a proposal contract, not an execution contract. Hermes may select one Host-provided candidate after bounded read-only analysis. The Host validates and persists the proposal. A proposal can only route the user into an existing preview/confirm workflow.

Allowed action types are:

- `organize_selected`: open the current snapshot-bound cluster organization preview;
- `export_knowledge_pack`: open a snapshot-bound knowledge-pack preview.

No model output can directly move, create, overwrite, delete, undo, pair, grant a capability, call a network destination, or execute an arbitrary tool.

## 2. Public card

A card exposes only `suggestion_id`, `action_type`, `category`, `title`, `reason`, `request`, `source`, `created_at`, `status`, and safe target presentation. Internal snapshot hashes, target references, asset IDs, paths, locators, model prompts, job IDs, and capability digests are excluded from the wire response.

`source` must be `hermes`; deterministic fallback may explain unavailability but must not masquerade as a proactive Hermes suggestion.

## 3. Trigger gate

Generation requires all of the following:

- explicit opt-in;
- the same authoritative Catalog snapshot observed for at least 10 seconds;
- no active suggestion for the same snapshot/candidate digest;
- no active write/undo recovery state;
- no category pause, 30-minute global cooldown, or daily limit of 3;
- at least one candidate whose existing capability and preview gates are satisfiable.

The first observation returns `stabilizing`. A transient failure returns one stable unavailable state. There is no background retry; the client may make one new user-triggered observation only after the network is stable.

## 4. Hermes tool boundary

`action_propose_typed_card` is a validation/submission tool. Its `action_type` and opaque `target_ref` must exactly match a Host candidate registered for the current job. Citations must belong to the current snapshot. Title, reason, and request are bounded product strings with path/URI/control-character rejection.

The validated tool payload is the only accepted proposal. Free-form assistant text and model reasoning are discarded.

## 5. State and privacy

Suggestion states are `available`, `accepted`, and `dismissed`. Accepting does not execute the action. Dismissal increments only category/day counters. The database stores hashes and bounded product copy, never source bodies, absolute paths, URIs, credentials, or chain-of-thought.
