[![Build Status](https://dev.azure.com/mwc-project/MWC%20Project/_apis/build/status/mwcproject.mwc-node?branchName=master)](https://dev.azure.com/mwc-project/MWC%20Project/_build/latest?definitionId=2&branchName=master)
[![Telegram Chat](https://img.shields.io/badge/chat-on%20telegram-brightgreen.svg?logo=telegram)](https://t.me/joinchat/IJTzpk33q3uBnautDTC5Sw)
[![Discord Chat](https://img.shields.io/discord/539232227360243712.svg?label=chat&logo=discord)](https://discordapp.com/invite/eUNwqf3)
[![Documentation Wiki](https://img.shields.io/badge/doc-wiki-blue.svg)](https://github.com/mwcproject/docs/wiki)
[![Release Version](https://img.shields.io/github/release/mwcproject/mwc-node.svg)](https://github.com/mwcproject/mwc-node/releases)
[![License](https://img.shields.io/github/license/mwcproject/mwc-node.svg)](https://github.com/mwcproject/mwc-node/blob/master/LICENSE)

# MWC

MWC is an in-progress implementation of the MimbleWimble protocol forked from Grin. Many characteristics are still undefined but the following constitutes a first set of choices:

  * Clean and minimal implementation, and aiming to stay as such.
  * Follows the MimbleWimble protocol, which provides great anonymity and scaling characteristics.
  * Cuckoo Cycle proof of work in two variants named Cuckaroo (ASIC-resistant) and Cuckatoo (ASIC-targeted).
  * Relatively fast block time: one minute.
  * Fixed block reward over time with a decreasing dilution.
  * Transaction fees are based on the number of Outputs created/destroyed and total transaction size.
  * Smooth curve for difficulty adjustments.

To learn more, read our [introduction to MimbleWimble and Grin](doc/intro.md).

## Status

MWC's mainnet has not launched. Much is left to be done and [contributions](CONTRIBUTING.md) are welcome (see below). Check our [mailing list archives](https://lists.launchpad.net/mimblewimble/) for the latest status.

## Contributing

To get involved, read our [contributing docs](CONTRIBUTING.md).

## Getting Started

To learn more about the technology, read our [introduction](doc/intro.md).

To build and try out MWC, see the [build docs](doc/build.md).

## Philosophy

The goal of MWC is to build out Mimblewimble technology in a way that benefits Bitcoin holders. We gave away 6,000,000 of the total 20,000,000 MWC that will ever exist to Bitcoin holders and another 2,000,000 will be given away as part of the HODL program. We respect the Grin developers, but wanted to take a different approach. We stated our disagreements clearly to the Grin team and are moving on in the direction we envision.

## Credits

Tom Elvis Jedusor for the first formulation of MimbleWimble.

Andrew Poelstra for his related work and improvements.

John Tromp for the Cuckoo Cycle proof of work.

The [Grin developers](https://github.com/mimblewimble) for undertaking the foundation of this project.

J.K. Rowling for making it despite extraordinary adversity.

## License

Apache License v2.0.

