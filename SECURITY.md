# MWC's Security Process

MWC has a code of conduct and the handling of vulnerability disclosure is no exception. We are committed to conduct our security process in a professional and civil manner. Public shaming, under-reporting or misrepresentation of vulnerabilities will not be tolerated.

## Responsible Disclosure

For all security related issues, MWC has 2 main points of contact:

* Chris Gilliard (christopher.gilliard@gmail.com)
* Konstantin Bay (konstantin.bay@gmail.com)

Send all communications to all parties and expect a reply within 48h.

## Vulnerability Handling

Upon reception of a vulnerability disclosure, the MWC team will:

* Reply within a 48h window.
* Within a week, a [CVVS v3](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator) severity score should be attributed.
* Keep communicating regularly about the state of a fix, especially for High or Critical severity vulnerabilities.
* Once a fix has been identified, agree on a timeline for release and public disclosure.

Releasing a fix should include the following steps:

* Creation of a CVE number for all Medium and above severity vulnerabilities.
* Notify all package maintainers or distributors.
* Inclusion of a vulnerability explanation, the CVE and the security researcher or team who found the vulnerability in release notes and project vulnerability list (link TBD).
* Publicize the vulnerability commensurately with severity and encourage fast upgrades (possibly with additional documentation to explain who is affected, the risks and what to do about it).

_Note: Before MWC mainnet is released, we will be taking some liberty in applying the above steps, notably in issuing a CVE and upgrades._

## Recognition and Bug Bounties

As of this writing, MWC is a **traditional open source project**. A bounty may be awarded should a vulnerability be disclosed.
* Advertising the vulnerability, the researchers, or their team on a public page linked from our website, with a links of their choosing.
* Acting as reference whenever this is needed.
* Setting up retroactive bounties whenever possible.

It is our hope that after mainnet release, participants in the ecosystem will be willing to more widely donate to benefit the further development of MWC. When this is the case we will:

* Setup a bounty program.
* Decide on the amounts rewarded based on available funds and CVVS score.

## Code Reviews and Audits

While we intend to undergo more formal audits before release, continued code reviews and audits are required for security. As such, we encourage interested security researchers to:

* Review our code, even if no contributions are planned.
* Publish their findings whichever way they choose, even if no particular bug or vulnerability was found. We can all learn from new sets of eyes and benefit from increased scrutiny.
* Audit the project publicly. While we may disagree with some small points of design or trade-offs, we will always do so respectfully.

## Forks and other modifications of MWC

We will responsibly disclose any vulerabilities in MWC to any forks of MWC and Mwc after they have been incorporated into a release of MWC. We will notify users that the release has fixes to a vulnerability so upgrades can be prioritized, but we will not release details of vulnerability until forks have had time to patch and release fixes to these vulnerabilities. We will disclose to all forks we are aware of. Maintainers may contact the security contacts to make us aware of your fork.

## Useful References

* [Reducing the Risks of Catastrophic Cryptocurrency Bugs](https://medium.com/mit-media-lab-digital-currency-initiative/reducing-the-risk-of-catastrophic-cryptocurrency-bugs-dcdd493c7569)
* [Security Process for Open Source Projects](https://alexgaynor.net/2013/oct/19/security-process-open-source-projects/)
* [Choose-Your-Own-Security-Disclosure-Adventure](http://hackingdistributed.com/2018/05/30/choose-your-own-security-disclosure-adventure/)
* [CVE HOWTO](https://github.com/RedHatProductSecurity/CVE-HOWTO)
* [National Vulnerability Database](https://nvd.nist.gov/)

