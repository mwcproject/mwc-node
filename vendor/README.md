# Arti vendor patches

Reviewed against the published Arti 0.48.0 crates at source commit
[`7c038125baef924a4bf287429c192c5af606f79c`](https://gitlab.torproject.org/tpo/core/arti/-/tree/7c038125baef924a4bf287429c192c5af606f79c).

| Patch used with Arti 0.47 | Status in the Arti 0.48 dependency stack | Action |
| --- | --- | --- |
| `saturating-time` 0.5.0: Windows clock limit search could loop forever; successful checked arithmetic eagerly evaluated the limit. | `tor-netdoc` 0.48.0 requires `saturating-time` 0.6.0. Its limit search handles unchanged clock values and its arithmetic uses lazy fallbacks. | Removed the vendor copy and override; use the fixed registry release. |
| `tor-ptmgr` 0.47.0: dropping a quiet transport could leave its child running; forced termination did not reap the child. | The published 0.48.0 `src/ipc.rs` is unchanged from 0.47.0. | Updated the vendor crate to 0.48.0 and retained the process supervisor and regression test. |

The two former `saturating-time` regression tests (100 ns clock precision and
lazy limit evaluation) were run against a temporary copy of published 0.6.0,
without any runtime code changes. Both passed, as did its existing unit tests
and documentation tests. This simulates the Windows rounding behavior on other
platforms; it does not replace a native Windows build.

See [`tor-ptmgr/MWC-PATCH.md`](tor-ptmgr/MWC-PATCH.md) for the retained patch and
its removal criteria. The node's existing ten-second Arti runtime shutdown
allowance remains in place for its bounded transport cleanup.
