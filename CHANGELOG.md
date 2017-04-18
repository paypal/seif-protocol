# Change Log
All notable changes to this project will be documented in this file.

# [1.0.2] - 2017-04-17
### Added
- Support to send a buffer, JSON serializable object or an array of such as a message.
- Ability to generate multiple parties based on an entity's identity.
- White paper detailing Seif Protocol specification.
- Contributing guidelines in CONTRIBUTING.md
- CHANGELOG.

### Changed
- seif-protocol version reset to 0.
- All data on the wire are now Seif Blobs. A Seif Blob contains two bytes indicating length of a buffer representing a serialized JSON, the buffer itself and finally any buffers described in the JSON.
- Keys and secrets part of handshake messages sent as buffers.
- Reduced message types to `send` and `statusSend`.
- Removed support for sessions with pre-authorization.
- Initiating `hello` includes an unencrypted field `connectionInfo` providing optional context to a connection.
- Removed redirect with the use of pre-authorized sessions and updated redirects now establish new connections with possible context provided in `connectionInfo` which is part of an initiating `hello`.
- Identity creation reflects strength of entropy pool used.
- Necessary changes made to be compatible with seifnode 1.0.3.
