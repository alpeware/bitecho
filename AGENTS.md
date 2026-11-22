* **Rule 1: Strict TDD.** Write generative tests (`clojure.test.check`) for invariants *before* implementing core logic. Extend model-based `test.check` command-sequence tests (including stale-generation callbacks and failure injection) to shell lifecycle boundaries.
* **Rule 2: Pure Functions.** The core must remain pure (Sans-IO). Side effects are strictly isolated to boundary shells.
* **Rule 3: Clean CI.** PRs must run `clojure -M:format` and `clojure -M:lint` successfully before submission. Do not ignore linter warnings.
* **Rule 4: Single-Authority Shell Lifecycle State.** Never split connection/session liveness across competing atoms or persist derived runtime liveness (`:connected?`, `:connection-error`) to disk. Model shell connection state in a single generation-tagged map updated by a pure `(transition conn event) -> [new-conn effects]` reducer, executing effects (`:close-node`, `:emit`, `:diagnose`) outside the state transition and ignoring stale generations (`gen < current`).
* **Rule 5: Zero Silent Failures.** Never drop envelopes, ignore stale callbacks, or fail dials silently. Every dropped envelope, ignored stale callback, or failed dial must emit a counted `:diagnose` effect surfaced in status diagnostics (`:phase`, `:generation`, `:last-error`, `:dropped`).
* **Rule 6: Co-Committed Ops, Spec, and Flag Inventory.** Behavioral or CLI changes must update spec, docs, ops scripts, and tests in the same commit. Ops scripts must assert preconditions loudly, and CLI/protocol verbs and flags must be verified by automated flag-inventory tests.

## Build, Format, Lint & Test Commands

This repository does **NOT** use `shadow-cljs` (never invoke `npx shadow-cljs`). All ClojureScript bundles are built with vanilla `org.clojure/clojurescript` (`cljs.main`) via the scripts in `scripts/`.

* **Format & Lint (required before commit):**
  * `clojure -M:format`
  * `clojure -M:lint`
* **Tests:**
  * Full JVM suite: `clojure -M:test`
  * Single namespace: `clojure -M:test -n bitecho.d45-bip018-hardening-and-failover-test`
  * ClojureScript suite: `clojure -M:test-cljs`
  * Deterministic VOPR/Jepsen suite: `clojure -M:jepsen`
* **Builds:**
  * Node.js full-node bundle (`dist/bitecho-full-node.cjs`): `./scripts/build-full-node-bundle.sh`
  * Node.js light-node bundle (`dist/bitecho-light-node.cjs`): `./scripts/build-node-light-node.sh`
  * Browser bundle (`dist/bitecho-browser.js`): `./scripts/build-browser-bundle.sh`
  * JVM uberjar (`target/bitecho.jar`): `clojure -T:build uber`

## Recurring Pitfalls & Conventions

* **CLJS `sorted-map` mixed-key lookups:** Never probe a keyword key directly on an arbitrary map that may be a string-keyed `sorted-map` (e.g., `:petnames`); use `safe-map-get` in generic walkers/sanitizers to avoid CLJS `CompareError`.
* **Public blameless postmortems:** Production incidents must be documented under `docs/postmortems/INC-YYYY-MM-DD-<slug>.{md,edn}` (and indexed in `docs/postmortems/index.edn`) so they are served publicly via `/incidents/*`.
