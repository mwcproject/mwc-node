# A Standard for Responsible Disclosure in Cryptocurrency and Related Software

## Background
Cryptocurrencies represent a radical shift from the legacy financial system and as a result provide an opportunity to help reshape the finance world. It is essential to recall that cryptocurrencies represent real money and introducing bugs and security vulnerabilities can cost users a significant amount of money, but ultimately hurt all other participants in the space.

There are several open source projects with common code, with shared goals of expansion in capability and investment, driven by market confidence in their integrity, that would benefit from a safe and well-defined vulnerability sharing processes.

For this reason, we have formalized a Responsible Disclosure policy that sets a standard for how organizations can share vulnerability information ethically, responsibly and for the good of the ecosystem.

## Guiding Principles
- We recognize that prior to mainstream adoption of cryptocurrencies, the safety and associated growth of the ecosystem of technologies is more important than competition within the space, at least when considering security vulnerability information.
- We recognize that universal adoption of basic security responses to disclosures is vital to the prosperity of the ecosystem and by extension every member of it.
- We recognize that this standard must reflect and respect the complexities of the crypto ecosystem and provide the opportunity for organizations to adhere to their own values and working practices beyond this basic standard.

## Purpose
This standard is intended to set the expectations and limitations of the disclosure process and each party’s participation in it, to reduce the effort and confusion involved in disclosing vulnerabilities, and to encourage participation in vital security practices for the benefit of all participants.

## How to use this standard

1. Read the standard in full
2. Decide if you agree with its principals and processes enough to commit to it. Feedback is welcome.
3. If you would like to, publicly commit to the disclosure process and your disclosure relationships.
4. Mention any ways in which you plan to deviate from the standard. The standard provides for some wiggle room to accomodate the specifics of the variety of technologies in the cryptocurrency space. If you intend to deviate from this ethical standard, it might make it easier to justify those decisions if you publicise them before you later come to rely on them. This also makes the disclosure process easier to understand for anyone reporting a bug to you.

### Publicly Committing to Disclosure Process
To commit to this standard it requires that your published disclosure process include an addendum section that outlines policies specific to your project.

1. Your preferred contact method (eg. email to a security@ address)
2. How to use that contact method securely (eg. full public key)
3. Details of any bug bounty program if you have one, and what it does or does not cover (you can link to another single page that contains these details).
4. Your list of neighboring projects who you will disclose to if you find an issue or if an issue is disclosed to you that might affect their products too.
5. A link to this standard.
6. The date that your commitment was last updated.

### Publicly Committing to Disclosure Relationships
To provide ecosystem cohesion and the expectation of cooperation and timely delivery of vulnerability information, each participating organization will publicly commit to making disclosures that may affect related projects (‘neighbors’). This does not limit any participating organization from responsibly disclosing to other organizations, provided that they follow the other provisions and restrictions of this standard when doing so. This does not require that projects share vulnerability information before they have fixed that issue in their own project(s), if they are vulnerable.

Committing to disclosure relationships serves the purpose of setting the expectation of sharing by proxy to those parties should it be likely they are also affected by a disclosed bug. The intention is that all disclosed-to parties will collaborate on fixes, release updates together, then release vulnerability details together in concert with the disclosing party.

If the projects you have disclosure relationships with also commit to this standard, link to their page stating that commitment. Otherwise link to any page with their disclosure contact details on.

## The Standard
To adhere to this standard, your organization will need to publish a document describing your disclosure process and follow the basic practices involved. This document is a suggested starting point. Publishing can be achieved using GitHub, but wherever it is published it should be possible to link directly to it with a static url so that it can be linked by other participating organizations. 

### Ethical Behavior
Responsible disclosure is predicated on ethical behavior. These guidelines outline best practices for the community as whole, whether you are reporting, or the recipient of a report. By stating that you adhere to this policy, you’re claiming to handle vulnerability information ethically, and abide by the following:

- Do not attempt to leverage a vulnerability, or information of its existence, as part of a financial trading strategy or otherwise for financial gain.
- Do not attempt to compromise systems upon which development of a product relies; including but not limited to compromising development systems, accounts, domains, email etc..
- Do not attempt to sell vulnerability information or exploits.
- Do not ask for any form of compensation from an affected party.
- You may compensate a disclosing party if you would like to after all known vulnerability details have been disclosed.
- Do not disclose a bug or vulnerability on mailing lists, public boards, forums, social media or any other channel prior to Responsibly Disclosing to the organizations you have a published relationship with
- Do not attempt any illegal acts, including phishing, physical attacks, DDoS, or any attempt to gain access without authorization

### Standard Disclosure Timelines
Some vulnerabilities take more time to fix than others, and some organizations are able to switch tasks to fixes faster than others, and this ability tends to fluctuate over time.

### Initial Contact
To disclose to a neighbor that you have an existing relationship with, you must contact them via their published contact details using the security procedures that they have published. If you get no response within two working days, you must try another two times with an interval of two working days each time. If you get no acknowledgement to those messages, you may optionally decide to attempt to reach them using other methods, but you must not include details of the vulnerability unless you are using their approved secure communication method.

If there is no response after your initial contact attempts, you should send another message saying that there has been no response to your (at least three) messages and setting a date for public disclosure that is not more than 90 days or less than 60 days in the future. If you receive a response during that time, both parties can agree to change the disclosure date in accordance with the rest of this process.

### Giving Details
After you receive a response to your initial contact, you should disclose the details of the vulnerability to the potentially affected party, along with reasons you think they may be affected and any advice you have on how to fix the issue.
Once you have made initial contact, you are expected to provide all the technical details about the vulnerability within two working days of receiving acknowledgement of your initial contact.

Your report should include:
- A PGP encrypted email to maintainers
- Description of suspected vulnerability
- Steps to reproduce the issue
- Your email address and a secure mechanism to contact you
- Your name and/or colleagues if you wish to be later recognized
- Optionally a patch and/or suggestions to resolve the vulnerability

### Setting Dates
After you have provided details of the issue to your neighbors, you both should agree on a date to release updates and a date to publicize the details of the issue. Issues that require only a small change should correspond with a date relatively soon after giving details - somewhere between 30 and 60 days. Issues that require a more significant investment by both parties might result in a date set up to 90 days in the future.

Parties involved in the disclosure should have the expectation of negotiating publishing dates with all of their neighbors that share the affected code, even if it turns out that those neighbors are not vulnerable for some other reason not known at the time.

It is up to each organization to determine their level of vulnerability to any disclosed issue, and rate issues accordingly. In general though, spend bugs should be considered very high priority - users losing access to their funds is precisely what this standard is intended to address.

It is up to each organization to notify their users of the availability of a fix and migrate their user base to the fixed version.

### Coordinated Release
When executed faithfully, the intention of this standard is to have all affected parties release a fix for an issue to their users together, and then all release details of the vulnerability together after a period of time that everyone can agree on.

In practice this is not always possible, and sometimes it will be necessary to release when one or more parties are not ready. Without the threat of public release of vulnerability information, organizations aren’t always incentivized to act in good faith for the security of their users.

Once the dates are set, the clock is very much ticking: When the release date comes around, any and all participating parties should release the vulnerability information regardless of the availability of fixes and the adoption rate of their user base.

Responding with appropriate development resources to fix security bugs, implementing a user contact system, and an update system that can perform in this time-limited scenario is down to each participating organization.

At time of release, participants should make a reasonable effort to discreetly patch. Avoid language that can draw undue attention to commits & PRs, or consider embedding the fix among other updates.

### Bounty Payments
Parties that have been disclosed to may, at their discretion, decide to pay a bounty to a disclosing party, but within the limits of their existing relationship (in the case of a neighbor), or their published bug bounty program (in the case of anyone else). Organizations implementing this standard may not attempt to coerce payments or sell bugs (see the section on “Ethical Behavior”). 

### Acknowledgements
If the reporting individual or organization would like to be recognized for their discovery, they may do so after the disclosure timeout. At the discretion of each participating team, a list of these individuals and/or organizations may recognize vulnerabilities disclosed responsibly.

### Reference links:
https://medium.com/mit-media-lab-digital-currency-initiative/reducing-the-risk-of-catastrophic-cryptocurrency-bugs-dcdd493c7569  
https://medium.com/mit-media-lab-digital-currency-initiative/http-coryfields-com-cash-48a99b85aad4  
https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-September/015036.html  
http://bitcoincore.org/en/contact  
https://lists.linuxfoundation.org/pipermail/bitcoin-dev/  
https://www.reddit.com/r/btc/comments/6zf1qo/peter_todd  
https://www.reddit.com/r/btc/comments/6z827o/chris_jeffrey  
https://www.reddit.com/r/btc/comments/6zb3lp/maxwell  
https://lists.linuxfoundation.org/pipermail/bitcoin-dev/  
http://luke.dashjr.org/programs/bitcoin/files/charts/branches.html  



