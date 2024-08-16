[![Build Status](https://dev.azure.com/mwc-project/MWC%20Project/_apis/build/status/mwcproject.mwc-node?branchName=master)](https://dev.azure.com/mwc-project/MWC%20Project/_build/latest?definitionId=2&branchName=master)
[![Chat](https://img.shields.io/discord/539232227360243712)](https://discord.gg/n5dZaty)
[![Support](https://img.shields.io/badge/support-on%20Discord-brightgreen.svg)](https://discord.gg/n5dZaty)
[![Documentation Wiki](https://img.shields.io/badge/doc-wiki-blue.svg)](https://github.com/mimblewimble/docs/wiki)
[![Release Version](https://img.shields.io/github/v/release/mwcproject/mwc-node.svg)](https://github.com/mwcproject/mwc-node/releases)
[![License](https://img.shields.io/github/license/mwcproject/mwc-node.svg)](https://github.com/mwcproject/mwc-node/blob/master/LICENSE)

# MWC

MWC is an in-progress implementation of the MimbleWimble protocol. Many characteristics are still undefined but the following constitutes a first set of choices:

  * Clean and minimal implementation, and aiming to stay as such.
  * Follows the Mimblewimble protocol, which provides hidden amounts and scaling advantages.
  * Cuckoo Cycle proof of work in two variants named Cuckaroo (ASIC-resistant) and Cuckatoo (ASIC-targeted).
  * Relatively fast block time: one minute.
  * Block rewards decrease at regular intervals, until the total supply of coins reaches the fixed limit of 20 000 000 MWC.
  * Transaction fees are based on the number of Outputs created/destroyed and total transaction size.
  * Smooth curve for difficulty adjustments.

To learn more, read our [introduction to MimbleWimble](doc/intro.md).

## Status

Much is left to be done and [contributions](CONTRIBUTING.md) are welcome (see below).

## Contributing

To get involved, you can read our [contributing docs](CONTRIBUTING.md).

## Getting Started

To learn more about the technology, read our [introduction](doc/intro.md).


To build and try out MWC, see the [build docs](doc/build.md).

## Credits

Tom Elvis Jedusor for the first formulation of MimbleWimble.

Andrew Poelstra for his related work and improvements.

John Tromp for the Cuckoo Cycle proof of work.

## License

Apache License v2.0.

