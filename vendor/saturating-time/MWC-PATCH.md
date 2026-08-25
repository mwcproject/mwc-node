# MWC Windows patch

This directory is based on `saturating-time` 0.4.0, commit
`1ba4c02c398e290487098c36b75995033327a06a`.

Arti 0.44 and newer call `SystemTime::saturating_sub` while parsing a network
consensus. The upstream implementation eagerly calculates `SystemTime`'s
minimum value, whose limit search never terminates on Windows: Windows stores
`SystemTime` in 100 ns intervals, so a 1 ns subtraction succeeds without
changing the value.

The local patch:

- calculates saturation limits only when checked arithmetic actually fails;
- terminates the limit search when a platform rounds a step to no change;
- makes the crate's tests account for platform clock precision.

Remove the workspace override after these changes are available in a released
upstream version and the Arti dependency range selects that release.
