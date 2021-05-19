DAPS version 1.0.3 is now available from:

  <https://github.com/DAPSCoin/DAPSCoin/releases>

This is a new minor-revision version release, including various bug fixes and
performance improvements, as well as updated translations.

Please report bugs using the issue tracker at github:

  <https://github.com/DAPSCoin/DAPSCoin/issues>


How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely shut down (which might take a few minutes for older versions), then run the installer (on Windows) or just copy over /Applications/DAPScoin-Qt (on Mac) or dapscoind/dapscoin-qt (on Linux).


Compatibility
==============

DAPS is extensively tested on multiple operating systems using
the Linux kernel, macOS 10.12+, and Windows 7 and newer. It is not recommended
to use DAPS on unsupported systems.

Microsoft ended support for Windows XP on [April 8th, 2014](https://www.microsoft.com/en-us/WindowsForBusiness/end-of-xp-support),
No attempt is made to prevent installing or running the software on Windows XP, you
can still do so at your own risk but be aware that there are known instabilities and issues.
Please do not report issues about Windows XP to the issue tracker.

DAPS should also work on most other Unix-like systems but is not
frequently tested on them.


Notable Changes
===============

Automated Database Corruption Repair
---------------------
There have been cases of blockchain database corruption that can occur when DAPS client is not closed gracefully. The most common cases of corruption have been identified and the wallet will now automatically fix most of these corruptions. Certain corruption states are still unable to be fixed, but now provide more detailed error messages to the user as well as prompting the user to reindex their database.

More Accurate Error Messages
---------------------
Some error messages in the wallet have been too vague and done little to help developers and the support team properly identify issues. Error messages have been refined and are now more specific.

Reduction of Debug Log Spam
---------------------
Many 3rd party services have reported that their debug logs have been overloaded with messages about unknown transaction types. This log spam has been fixed.

Removal of Heavy Running Transaction Search Code
---------------------
Many areas of the block validation code use a "slow" transaction search, which searches redundantly for transactions. This "slow" search has been removed upstream in Bitcoin and is now removed in DAPScoin. This provides a more efficient syncing process and generally better performing wallet.

Working Testnet
---------------------
Testnet is now accessible with this release of the wallet. Testnet can be accessed using the `-testnet` startup flag.

Credits
=======

Thanks to everyone who directly contributed to this release:
- Fuzzbawls
- Jon Spock
- Mrs-X
- Patrick Collins
- PeterL73
- presstab
- sonic
- whateverpal

As well as everyone that helped translating on [Transifex](https://www.transifex.com/projects/p/dapscoin-project-translations/).
