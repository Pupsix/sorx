# Changelog

## [0.1.0] - 2026-08-28

### Added

* First usable release of `sorx`.
* Basic CORS analysis.
* Active CORS scanning with `quick`, `normal`, and `deep` modes.
* Target URL and target list support.
* Multi-threaded scanning.
* Request timeout.
* Text and JSON output.
* Basic error handling.

### Notes

* Early development release.
* Limited functionality.
* Some features and detection rules may not work as expected.
* CLI and output behavior may change in future releases

## [0.1.1] - 2026-08-28

### Fixed

* Fixed incorrect usage instructions in the README.

## [0.1.2] - 2026-08-29

### Added

* Added trusted-domain payload generation.
* Added `--rule` and `--verbose` flags.

## [0.2.0] - 2026-08-30

### Added

- Added request rate limiting with `--rate`.
- Added configurable delay between requests with `--delay`.
- Added 2 new CORS detection rules.

### Improved

- Added more CORS payloads and reorganized payload formatting to improve test case coverage.
- Improved origin fuzzing to support IP addresses in addition to HTTPS hostnames.