# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Read the application version directly from `package.json` for footer rendering.
- Handle unfetchable `inReplyTo` values without returning 500 errors.

### Maintenance

- Updated npm dependencies and GitHub Actions dependencies.
- Simplified Dependabot configuration for GitHub Actions.
- Ignored local `data` directory.

## [0.19.2] - 2026-03-10

### Maintenance

- Updated `multer` and `minimatch`.

## [0.19.1] - 2026-03-10

### Fixed

- Made redirect URI checks more robust.

### Maintenance

- Updated package metadata and dependencies.

## [0.19.0] - 2025-11-08

### Added

- Added CIMD support.
- Added a CIMD flag to OAuth discovery.

## [0.18.5] - 2025-11-04

### Fixed

- Corrected actor ID handling in `User.updateAllUsers()`.

## [0.18.4] - 2025-11-04

### Fixed

- Handled empty owner values.

## [0.18.3] - 2025-11-04

### Fixed

- Ensured all users are public and self-owned.

## [0.18.2] - 2025-11-04

### Fixed

- Avoided mixing object and remote cache data.

## [0.18.1] - 2025-11-02

### Fixed

- Added the OAuth context.

## [0.18.0] - 2025-11-02

### Added

- Added ActivityPub universal client ID discovery.

## [0.17.0] - 2025-11-02

### Added

- Added OAuth discovery.
- Added Dynamic Client Registration.

### Maintenance

- Updated dependencies.

## [0.16.1] - 2025-09-16

### Maintenance

- Updated `mime`, `bootstrap`, and `config`.

## [0.16.0] - 2025-09-16

### Added

- Returned error results using Problem Details.

## [0.15.10] - 2025-08-18

### Fixed

- Replaced `req.headers.get()` with Express `req.get()`.

## [0.15.9] - 2025-08-18

### Fixed

- Fell back to the server ID for failure subjects.

## [0.15.8] - 2025-08-18

### Added

- Avoid retrying failed URLs for one hour.

## [0.15.7] - 2025-08-18

### Fixed

- Moved remote cache fixup logic into the fixup code.

## [0.15.6] - 2025-08-18

### Added

- Reduced the default SQLite3 cache size.

### Fixed

- Logged `db.init()` failures.

## [0.15.5] - 2025-08-18

### Added

- Cached a pool of `get` and `all` statements per request.
- Added new per-request `get` and `all` statement handling.

### Performance

- Tuned SQLite3 behavior.
- Reinstated automatic query preparation.

## [0.15.4] - 2025-08-18

### Added

- Moved remote objects from `object` storage to `remotecache`.

## [0.15.3] - 2025-08-18

### Fixed

- Cached remote activities without saving them as local objects.
- Checked for alternatives before loading full objects.

## [0.15.2] - 2025-08-18

### Performance

- Reverted automatic query preparation.

## [0.15.1] - 2025-08-18

### Performance

- Added an index to `user(actorId)`.
- Added automatic query preparation.

## [0.15.0] - 2025-08-18

### Fixed

- Added indices for addressee and upload data.

## [0.14.3] - 2025-08-18

### Added

- Added request duration and metadata to logs.

### Fixed

- Set CORS expiration to one day.

### Maintenance

- Logged content negotiation errors.

## [0.14.2] - 2025-08-17

### Fixed

- Used copies when expanding data.
- Moved cache metrics initialization closer to cache initialization.

## [0.14.1] - 2025-08-17

### Testing

- Added tests for `Link`, `Hashtag`, and `Mention` link types.

## [0.14.0] - 2025-08-16

### Maintenance

- Release version update only.

## [0.13.0] - 2025-08-16

### Added

- Supported WebFinger lookup for actor IDs.

## [0.12.13] - 2025-08-16

### Fixed

- Handled key rotation with the new `ActivityObject.get()` flow.

## [0.12.12] - 2025-08-15

### Fixed

- Fixed problems with updating collections.

## [0.12.11] - 2025-08-15

### Fixed

- Improved constructors for inbox and outbox in `User.internalUpdate()`.

## [0.12.10] - 2025-08-14

### Fixed

- Fixed up user collections internally.

## [0.12.9] - 2025-08-14

### Added

- Added fixup support for bad `attributedTo` and `to` values in user collections.

### Fixed

- Improved logging when user collections are updated.

## [0.12.8] - 2025-08-14

### Performance

- Added metering for more crypto and JSON tasks.

## [0.12.7] - 2025-08-14

### Performance

- Parallelized expansion of collection page items.
- Parallelized expansion of properties.

## [0.12.6] - 2025-08-14

### Added

- Added an app timer for full handler timing.

### Fixed

- Used cache and counter options when fetching owners and addressees.

## [0.12.5] - 2025-08-14

### Added

- Added timing output to the proxy endpoint.
- Counted crypto interaction time in JWT and HTTP Signature paths.

## [0.12.4] - 2025-08-14

### Fixed

- Checked key objects before using them in `HTTPSignature.validate()`.
- Showed collection item IDs when items cannot be fetched.

## [0.12.3] - 2025-08-14

### Added

- Used cache and counter data in `HTTPSignature.validate()`.

## [0.12.2] - 2025-08-14

### Fixed

- Used `ActivityPub.get()` for expanded objects.

## [0.12.1] - 2025-08-14

### Maintenance

- Updated dependencies.

## [0.12.0] - 2025-08-14

### Added

- Added `Server-Timing` header support for object GET requests.
- Added per-request cache support.
- Added a `complete` flag in remote cache records.
- Added a separate remote cache table.
- Added cache clearing on collection changes.
- Added remote delete and remote update support.
- Added improved brief object rendering.

### Changed

- Changed `ActivityObject.get()` to use an options map.
- Added subject and cache dependencies to the `ActivityObject` constructor.

### Fixed

- Left properties unexpanded when they cannot be loaded.
- Fixed `ActivityObject.get()` call sites in `toBrief()` and the proxy URL endpoint.
- Improved prepend handling for collections.
- Handled hashes in remote IDs.
- Improved empty JSON handling in objects.
- Fixed remote undo follow handling.

## [0.11.7] - 2025-07-16

### Maintenance

- Updated `supertest`.

## [0.11.6] - 2025-07-16

### Fixed

- Allowed WebFinger requests for the server actor.

### Documentation

- Linted `README.md`.

## [0.11.5] - 2025-07-10

### Fixed

- Allowed alternate representations of Public addressing.

## [0.11.4] - 2025-07-09

### Maintenance

- Switched linting from ESLint to StandardJS.
- Updated dependencies.

## [0.11.3] - 2025-07-09

### Added

- Added a fixup array for migration and repair tasks.

### Changed

- Refactored user activity handling.

### Fixed

- Used the standard Express CORS middleware.

## [0.11.2] - 2025-05-18

### Added

- Tolerated remote key rotation.

## [0.11.1] - 2025-05-16

### Fixed

- Lowercased headers and trimmed values during signature validation.

## [0.11.0] - 2025-05-14

### Added

- Added `preferredUsername` for the server actor.

## [0.10.6] - 2025-05-14

### Fixed

- Checked the cache for remote keys before fetching them.

## [0.10.5] - 2025-05-14

### Fixed

- Accepted digest values with incorrect capitalization.

## [0.10.4] - 2025-05-14

### Added

- Added debugging output for digest errors.

## [0.10.3] - 2025-05-13

### Added

- Showed warnings for errors in logs.

### Testing

- Made test output silent by default.

## [0.10.2] - 2025-05-13

### Fixed

- Checked for digest and date headers in HTTP Signature middleware.

## [0.10.1] - 2025-05-13

### Fixed

- Showed `publicKeyPem` for `Key` and `PublicKey` types.

## [0.10.0] - 2025-05-13

### Fixed

- Changed key output type from `Key` to `CryptographicKey`.

## [0.9.9] - 2025-05-13

### Fixed

- Expanded objects using owner or actor credentials.

## [0.9.8] - 2025-05-12

### Fixed

- Passed IDs correctly to response handlers.

## [0.9.7] - 2025-05-12

### Fixed

- Checked for null `publicKey` values in `HTTPSignature.validate()`.
- Added GitHub Actions workflow permissions.

### Maintenance

- Updated dependencies.

## [0.9.6] - 2025-05-12

### Added

- Ignored VS Code files.

### Fixed

- Avoided authenticating key requests when authentication is unnecessary.
- Downgraded ESLint from 9 to 8.

### Maintenance

- Updated dependencies.

## [0.9.5] - 2024-09-07

### Maintenance

- Updated dependencies.

## [0.9.4] - 2024-09-07

### Added

- Added a lint command.

### Fixed

- Improved handling of unexpected signature algorithms.

### Maintenance

- Switched to StandardJS.

## [0.9.3] - 2024-08-26

### Fixed

- Used the v1 security context.

## [0.9.2] - 2024-08-26

### Fixed

- Ensured `@context` is the first property.

## [0.9.1] - 2024-08-26

### Fixed

- Moved context output to the top of responses.

## [0.9.0] - 2024-08-26

### Added

- Added the miscellany context.

### Fixed

- Added CORS support.

### Changed

- Used default tools for retrieving remote clients.

### Maintenance

- Updated dependencies.

## [0.8.2] - 2024-01-14

### Added

- Showed more client details on the OAuth authorization page.

### Changed

- Removed the Helm chart after moving it to its own repository.

## [0.8.1] - 2024-01-09

### Fixed

- Made inbox delivery add the owner as an implicit addressee.

## [0.8.0] - 2024-01-09

### Added

- Added support for the WebFinger extension.

## [0.7.3] - 2024-01-08

### Added

- Refused activities when the actor ID does not match the signature ID.

### Fixed

- Made user checks more robust.

## [0.7.2] - 2024-01-08

### Fixed

- Fixed remaining fixup code issues.

## [0.7.1] - 2024-01-08

### Fixed

- Fixed update code for server keys.

## [0.7.0] - 2024-01-08

### Added

- Added a server key.
- Used the server key for HTTP Signatures when no other key is available.

### Changed

- Refactored server handling into a `Server` class.
- Changed database initialization.

### Fixed

- Ensured server keys use PKCS8/SPKI formats.
- Improved title handling for tag actions.

### Maintenance

- Updated dependencies.

## [0.6.4] - 2024-01-07

### Added

- Added Digest headers to HTTP Signatures.

### Maintenance

- Updated Helm chart version metadata.

## [0.6.3] - 2024-01-07

### Fixed

- Converted PKCS1 keys to PKCS8 and SPKI.

### Maintenance

- Updated Helm chart metadata.

## [0.6.2] - 2024-01-07

### Fixed

- Emitted SPKI public keys.

### Maintenance

- Updated Helm chart metadata.

## [0.6.1] - 2024-01-07

### Added

- Updated `nanoid` from 4 to 5.
- Added more logging for proxy URL errors.

### Fixed

- Improved handling for unfound IDs in Update activities.
- Checked null values in `User.isUser()`.

### Maintenance

- Updated dependencies.

## [0.6.0] - 2023-11-04

### Added

- Copied addressees between Create activities and created objects.

### Testing

- Added coverage for liking uncached objects.

### Maintenance

- Updated Helm chart metadata.

## [0.5.1] - 2023-10-29

### Added

- Improved prepend handling and related collection behavior.

### Fixed

- Adjusted behavior to make tests pass.

### Maintenance

- Updated Helm chart metadata.

## [0.5.0] - 2023-10-29

### Added

- Added file uploads.
- Added collection pages.
- Generated signing keys.

### Maintenance

- Updated Helm chart metadata.

## [0.4.1] - 2023-10-27

### Fixed

- Handled HTTP Signatures whose key IDs include URL fragments.

### Maintenance

- Updated Helm chart metadata.

## [0.4.0] - 2023-10-24

### Changed

- Represented actor streams as strings instead of embedded objects.

### Maintenance

- Updated Helm chart metadata.

## [0.3.7] - 2023-10-22

### Added

- Included subject data in logs.

### Maintenance

- Updated Helm chart metadata.

## [0.3.6] - 2023-10-21

### Fixed

- Redirected unauthenticated OAuth authorization requests to login.

### Maintenance

- Changed the Helm chart to use the `0.3` tag by default.

## [0.3.5] - 2023-10-19

### Fixed

- Used the logger for serious errors.

### Maintenance

- Updated Helm chart metadata.

## [0.3.4] - 2023-10-19

### Fixed

- Removed a duplicate homepage headline.
- Avoided changing immutable PVC settings.

### Maintenance

- Updated application version metadata.

## [0.3.3] - 2023-10-19

### Fixed

- Made token endpoint media type checks more careful.
- Removed cruft from tag action handling.

### Maintenance

- Updated Helm chart metadata.

## [0.3.2] - 2023-10-19

### Fixed

- Corrected URLs behind a load balancer.
- Ignored `.DS_Store`.

### Maintenance

- Updated Helm chart metadata.

## [0.3.1] - 2023-10-10

### Documentation

- Documented additional environment variables.

## [0.3.0] - 2023-10-10

### Added

- Derived the application name from `OPP_ORIGIN`.

### Maintenance

- Updated Helm chart metadata.

## [0.2.2] - 2023-10-10

### Added

- Showed the software version in the footer.
- Included SHA tags for the latest Docker image.

## [0.2.1] - 2023-10-10

### Added

- Built Docker tags correctly.
- Ignored `values-*.yaml` files.

### Maintenance

- Updated dependencies.

## [0.2.0] - 2023-10-10

### Added

- Added OAuth authorization and OAuth endpoints in actors.
- Added login page and Bootstrap-based pages.
- Added Application objects as OAuth client IDs.
- Added support for activities with multiple types.
- Added implicit Create support.
- Added prevention of updates to collection properties and server-provided object properties.
- Added remote Create, Update, Delete, Like, Announce, Add, Remove, Follow, Accept, Reject, and Undo handling.
- Added pending follows, pending namespace, and following support.
- Added proxy URL endpoints for fetching remote data.
- Added blocklist file support.
- Added invite code support.
- Added Dockerfile, Docker Compose, multi-platform Docker builds, and cached Docker builds.
- Added Helm chart, proxy support, deployment defaults, liveness endpoint, and readiness endpoint.
- Added a test script to `package.json`.

### Fixed

- Checked JWT type and bearer token scope.
- Fixed registration and login forms.
- Added Location headers for created resources.
- Fixed user profile updates.
- Corrected submitted `ld+json` activity handling.
- Prevented page-property and server-provided property updates.
- Improved handling for multiple-type activities.
- Improved test server port selection and waits.
- Improved shutdown and Linux test process handling.
- Fixed Docker workflow permissions, repository naming, and build command arguments.
- Corrected default address and hostname handling.

### Documentation

- Updated installation instructions and README content.

### Maintenance

- Added Dependabot configuration.
- Updated dependencies.

## [0.1.0] - 2023-06-19

### Added

- Added the initial service endpoint.
- Added registration, WebFinger, actor, inbox, outbox, followers, following, liked, and JWT support.
- Added HTTP Signature public key and security namespace support.
- Added remote delivery of activities.
- Added privacy enforcement for collection members.
- Added Create, Update, Delete, Add, Remove, Like, Block, Announce, replies, and queue handling.
- Added blocked and pending namespace support.
- Added Undo handling for Like, Block, and Follow activities.

### Changed

- Refactored database, HTTP Signature, collection, activity, activity object, and user logic into classes and methods.
- Reworked object persistence and retrieval helpers.

### Fixed

- Corrected route URL generation and default port handling.
- Added ownership and addressee information for authorization.
- Improved remove-object splicing and re-follow errors.
- Fixed PURL URL handling.

### Documentation

- Added README, license, code of conduct, and conventional commit documentation.

### Testing

- Added test helpers and coverage for SSL, actors, remote delivery, registration, outbox distribution, followers, following, liked streams, and filtering.

### Maintenance

- Adopted StandardJS style.
- Updated local testing certificate and key.
