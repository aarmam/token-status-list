# Token Status List

A Java implementation of the [Token Status List specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list) and the Identifier List mechanism from [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).

This library provides two revocation mechanisms:
- **Status List**: Bit-array based status tracking for tokens (IETF OAuth Token Status List)
- **Identifier List**: Map-based identifier tracking for MSO revocation (ISO/IEC 18013-5:2021)

Both mechanisms support tokens secured by JSON Object Signing and Encryption (JOSE) or CBOR Object Signing and Encryption (COSE), such as JWT, SD-JWT VC, CBOR Web Token (CWT), and ISO mdoc.

## Features

- ✅ Status List implementation with 1, 2, 4, or 8-bit status values
- ✅ Identifier List implementation for MSO revocation
- ✅ JWT and CWT token formats
- ✅ ZLIB compression for Status Lists
- ✅ CBOR encoding support
- ✅ Signature verification
- ✅ Builder patterns for easy construction

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.aarmam</groupId>
    <artifactId>token-status-list</artifactId>
    <version>1.0.1</version>
</dependency>
```

## Status List Usage

### Creating a Status List

```java
// Create a status list with 16 entries using 1 bit per status
StatusList statusList = new StatusList(16, 1);

// Set statuses (0 = VALID, 1 = INVALID)
statusList.set(0, StatusType.INVALID);
statusList.set(1, StatusType.VALID);
statusList.set(3, StatusType.INVALID);

// For 2-bit status (supports VALID, INVALID, SUSPENDED, and custom)
StatusList statusList2Bit = new StatusList(12, 2);
statusList2Bit.set(0, StatusType.INVALID);
statusList2Bit.set(1, StatusType.SUSPENDED);
statusList2Bit.set(2, StatusType.VALID);

// Check status
int status = statusList.get(0); // Returns 1 (INVALID)
```

### Creating a Status List Token

```java
// Create a Status List Token in JWT format
StatusListToken token = StatusListToken.builder()
    .subject("https://example.com/statuslists/1")
    .issuedAt(Instant.now())
    .expiresAt(Instant.now().plus(30, ChronoUnit.DAYS))
    .timeToLive(Duration.ofHours(12))
    .statusList(statusList)
    .signingKey(privateKey)
    .keyId("key-1")
    .build();

String jwt = token.toSignedJWT();
String cwt = token.toSignedCWT(); // For CWT format
```

### Verifying and Extracting Status List

```java
// Verify JWT signature and extract status list
StatusList extractedList = StatusListToken.verifySignatureAndGetStatusList(
    jwtString,
    publicKey
);

// Check if a token at index 3 is revoked
boolean isRevoked = extractedList.get(3) == StatusType.INVALID.getValue();
```

### Encoding and Decoding

```java
// Encode to JSON
Map<String, Object> map = statusList.encodeAsMap(true);
String json = new ObjectMapper().writeValueAsString(map);

// Decode from JSON
StatusList decoded = StatusList.buildFromJson()
    .json(json)
    .build();

// Encode to CBOR
byte[] cbor = statusList.encodeAsCBOR();

// Decode from CBOR
StatusList decodedFromCbor = StatusList.buildFromCbor()
    .cbor(cbor)
    .build();
```

## Identifier List Usage

The Identifier List mechanism is used for MSO (Mobile Security Object) revocation as defined in ISO/IEC 18013-5:2021.

### Creating an Identifier List

```java
// Create an identifier list with optional aggregation URI
IdentifierList identifierList = new IdentifierList("https://example.com/aggregation");

// Add identifiers to revoke
byte[] identifier1 = "credential-123".getBytes(StandardCharsets.UTF_8);
byte[] identifier2 = "credential-456".getBytes(StandardCharsets.UTF_8);

identifierList.addIdentifier(identifier1);
identifierList.addIdentifier(identifier2);

// Check if an identifier is revoked
boolean isRevoked = identifierList.isRevoked(identifier1); // Returns true

// Remove an identifier from revocation list
identifierList.removeIdentifier(identifier1);
```

### Creating an Identifier List Token

```java
// Create an Identifier List Token in JWT format
IdentifierListToken token = IdentifierListToken.builder()
    .subject("https://example.com/identifierlists/1")
    .issuedAt(Instant.now())
    .expiresAt(Instant.now().plus(30, ChronoUnit.DAYS))
    .timeToLive(Duration.ofHours(12))
    .identifierList(identifierList)
    .signingKey(privateKey)
    .keyId("key-1")
    .build();

String jwt = token.toSignedJWT();
String cwt = token.toSignedCWT(); // For CWT format
```

### Verifying and Extracting Identifier List

```java
// Verify JWT signature and extract identifier list
IdentifierList extractedList = IdentifierListToken.verifySignatureAndGetIdentifierList(
    jwtString,
    publicKey
);

// Check if an identifier is revoked
byte[] credentialId = "credential-123".getBytes(StandardCharsets.UTF_8);
boolean isRevoked = extractedList.isRevoked(credentialId);

// For CWT format
IdentifierList extractedFromCwt = IdentifierListToken.verifySignatureAndGetIdentifierListFromCWT(
    cwtHexString,
    publicKey
);
```

### Creating IdentifierListInfo for MSO

```java
// Create identifier list info for an MSO's status element
byte[] identifier = generateUniqueIdentifier();
IdentifierListInfo info = IdentifierListInfo.builder()
    .id(identifier)
    .uri("https://example.com/identifierlists/1")
    .certificate(optionalCertificate) // Optional
    .build();

// Encode as CBOR for inclusion in MSO
byte[] cbor = info.encodeAsCBOR();

// Decode from CBOR
IdentifierListInfo decoded = IdentifierListInfo.buildFromCbor()
    .cbor(cbor)
    .build();
```

## Key Differences: Status List vs Identifier List

| Aspect | Status List | Identifier List |
|--------|-------------|-----------------|
| **Use Case** | General token status tracking | MSO revocation (ISO/IEC 18013-5:2021) |
| **Data Structure** | Bit array | Map of identifiers |
| **Token Type (JWT)** | `statuslist+jwt` | `identifierlist+jwt` |
| **Token Type (CWT)** | `statuslist+cwt` | `identifierlist+cwt` |
| **Claim ID (CWT)** | 65533 | 65530 |
| **Revocation Check** | Check bit at index position | Check if identifier is present |
| **Compression** | ZLIB compression | No compression |
| **Status Values** | 2, 4, 16, or 256 values | Binary (present = revoked) |
| **Content-Type** | `application/statuslist+cwt` | `application/identifierlist+cwt` |

## Specifications

- [IETF OAuth Token Status List (draft-ietf-oauth-status-list)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list)
- [ISO/IEC 18013-5:2021 - Personal identification — ISO-compliant driving licence — Part 5: Mobile driving licence (mDL) application](https://www.iso.org/standard/69084.html)

## Building

```shell
mvn clean install
```

## Running Tests

```shell
mvn test
```

## License

This project is licensed under the terms specified in the LICENSE file.