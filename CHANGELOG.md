# Changelog
This is the changelog for a [Gradle][] project TODO.

The changelog follows [Keep a Changelog v1.0.0][], i.e. each release has the
following sections (if non-empty):
- Summary: Git-commit message
- Added
- Changed
- Deprecated
- Removed
- Fixed
- Security

The versioning policy of this project follows [Semantic Versioning v2.0.0][].

## v0.0.1, 2026-01-07
Release 0.0.1

Release notes:
1. This release contains just one class with a huge main method and linear
   programming.
   IMHO that is okay for a minimal working example.
2. The code is not POJO (plain old java objects), instead some modules are imported
   from maven-central:
   1. "de.gematik.smartcards:de.gematik.smartcards.utils:1.0.3"  
      From that module some helper methods are used. It shouldn't be too difficult
      to substitute those by plain Java or similar functionality from other modules.
   2. "de.gematik.smartcards:de.gematik.smartcards.tlv:1.0.3"  
      This module is used to handle BER-TLV objects and can easily be
      substituted by similar modules from other sources.
   3. "de.gematik.smartcards:de.gematik.smartcards.crypto:1.0.3"  
      This module performs cryptographic operations with AES and elliptic curves
      with brainpool-curves.
      It shouldn't be too difficult (but maybe time-consuming) to substitute
      the functionality with code from e.g. [Bouncy Castle][].
   4. de.gematik.smartcards:de.gematik.smartcards.g2icc:1.0.3"  
      A module for handling Card-Verifiable-Certificates as specified by
      [gemSpec_PKI][].
      Those CV-certificates are rather specific.
      It is possible that the Internet doesn't provide a better open source
      software for handling those.
3. The code dealing with secure messaging is not generic.
   It is just enough to handle the task at hand.

[Bouncy Castle]:https://en.wikipedia.org/wiki/Bouncy_Castle_(cryptography)
[Gradle]:https://gradle.org/
[Keep a Changelog v1.0.0]:http://keepachangelog.com/en/1.0.0/
[Semantic Versioning v2.0.0]:http://semver.org/spec/v2.0.0.html
[gemSpec_PKI]:https://gemspec.gematik.de/docs/gemSpec/gemSpec_PKI/latest/#6
