# MWC Windows patch

This directory vendors `saturating-time` 0.5.0 from crates.io, source commit
[`ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087`](https://gitlab.torproject.org/tpo/core/arti/-/tree/ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087/crates/saturating-time).

## Upgrade review

Arti 0.47's `tor-netdoc` requires `saturating-time` 0.5.0, so the old 0.4.0
override would no longer apply. The 0.5.0 release moves this crate into Arti,
adds `web-time-compat` and Arti's lint configuration, and replaces the `nightly`
feature with `cfg(saturating_time_nightly)`. These upstream code and build changes
are retained; the original Clara Engler author and Codeberg repository metadata
are preserved in both manifests.
However, `saturating_add`/`saturating_sub` still eagerly evaluate the limits with
`unwrap_or`, and `find_limit` still loops when arithmetic returns the same value.
Neither part of the Windows fix has been incorporated upstream.

## Problem and local changes

Arti 0.44 and newer call `SystemTime::saturating_sub` while parsing a network
consensus. The upstream implementation eagerly calculates `SystemTime`'s
minimum value, whose limit search never terminates on Windows: Windows stores
`SystemTime` in 100 ns intervals, so a 1 ns subtraction succeeds without
changing the value.

The local patch:

- calculates saturation limits only when checked arithmetic actually fails;
- terminates the limit search when a platform rounds a step to no change;
- makes the crate's tests account for platform clock precision.

`limit_search_terminates_with_100ns_precision` simulates Windows rounding on
every host and bounds the operation count so a regression fails without hanging.
`checked_arithmetic_does_not_evaluate_limits` verifies that successful checked
arithmetic never evaluates either saturation limit. Existing native-clock tests
and doctests still cover saturation and time differences.

Remove the workspace override after these changes are available in a released
upstream version and the Arti dependency range selects that release.
