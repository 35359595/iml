# IML - Inverted Microledger

## Abstract

IML (Inverted Microledger) is a variant of [Decentralized identifiers](https://www.w3.org/TR/did-core/#dfn-decentralized-identifiers) and [DID Method](https://www.w3.org/TR/did-core/#dfn-did-methods) designed to provide highest level of security and privacy.
This document is and should be interpreted as DI/DID specifications until stated otherwise.

## Status

Both specifications and reference implementation (also part of this repository) are in draft state. Version of the draft is equal to crate version specified in Cargo.toml file.

## 1. Introduction

There are dozens of Decentralized identifiers and DID methods defined already, but there are multiple issues with regards to different requirements associated with those.
Some are immutably put by Identifier to a blockchain, some can not operate without exposing Identifier to network layer (anyone who can intercept network packages is able to parse it out). Another issue is that some DID Methods require 
access to remote server in order to resolve DID Documents or verify validity of Identifier at hand, on the other hand - those which provide offline resolution have very limited capabilities and have security concerns.

The specifications provided here are targeted to remove all those issues and concerns and provide ways to guarantee Identifier exposure only to destined recipient and prevent it been revealed to any 3-rd party without explicit consent.
However, doing so, method may impend some extra resource costs - additional cryptographic operations and bigger (than other) DID URL sizes.

### 1.1 Objectives

* Prevent (as much as technologically possible) Identifier to be revealed to 3-rd parties during interactions with peers;
* Allow Identifier to change controlling key sets on demand;
* Allow Identifier to change content of related DID Document;
* Enable Identifier to attach any arbitrary data with cryptographically proven validity and consistency of the data (Attachments);
* Enable Identifier to selectively disclose any of the Attachments within any interaction or withhold them if not required by interaction to succeed;
* Provide DID Method which will prevent any time-message correlation attacks or any other type of deduction of who uses what;
* Do all the above with maximum performance and minimum possible message sizes;

### 1.2 Cryptographic algorithms

IML uses [ECDSA/P256](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) signatures for both `Iml` and `Attachment` `proof` generation.
For interactions `Iml` is encrypted using ephemeral Diffie-Hellman key exchanges with the secp256k1 elliptic curve.

### 1.3 IML Data Model

IML has main object named `Iml`, which is serializable. IML supports [CBOR](https://www.rfc-editor.org/rfc/rfc8949.html) serialization ONLY.
This is due to a fact that all properties are sets of raw bytes or guaranteed UTF-8 strings. In addition, during interaction, entire inner Iml of the envelope is deflated using DEFLATE algorithm to minimize data transferred over network.

IML uses recursion to provide consistent, uninterrupted chain of events, which is easy to parse and verify. Recursive property of `Iml` structure is named `inversion` and is OPTIONAL set of bytes produced from serializing previous Iml state.

`Iml` also have `id` property, which is OPTIONAL string value representing Identifier itself (present ONLY on civilization 0 and is Blake3 hash of initial signing key), or key reference when been sent to peer. In all other `Iml` civilization is absent.

Verifying key, which is pair of signing key used to `proof` sign current `Iml` is located as raw set of bytes under `current_sk` property.

Next committed verifying key, which is used during `evolution` is located as raw set of bytes under `next_sk` property.

`interaction_key` property is OPTIONAL, present and used only during interaction and contains PUBLIC (Encoded point) key of Identity holder's DH Secret key.

`civilization` property is used to indicate current level of `evolution` of identifier and is used to detect `degraded` attacks for known parties. unsigned 64 bit integer is used.

`attachments` property is OPTIONAL set of `Attachment`s.

`proof_of_attachment` is OPTIONAL set of bytes of the attachments signature and is used to validate attachments, which may be delivered separately from `Iml`;

`proof` is property of `Iml`, which is a set of bytes of signature generated from all non-OPTIONAL fields serialized as CBOR bytes.

#### 1.3.1 IML Attachment Data Model

'parent' - unsigned 64 bit integer of parent `Iml`s `civilization` property.

`payload` - set of bytes of any desired information;

`payload_type` - UTF-8 string indicating type of attached data. Reserved values apply.

`proof` - similar to `Iml`s proof - signature, generated from CBOR serialized data, using same key as for `parent` event signing.

## 2. Identifier Lifecycle

Lifecycle of Identifier starts from generation of two pairs of cryptographic keys, which are safely stored in chosen Key Vault. Key Vault itself is beyond the scope of this spec, however there are some common
security measures to key handling: keys used for Identity management should not be used for anything else or shared with any other entity or Identity. Ideally, these keys should never leave secure space of the
Key Vault and all crypto operations should be performed within Key Vault as well.

### 2.1 Civilization 0

As initial `Iml` creation - Verifying keys are set to `current_sk` and `next_sk` properties and it's `id` property is set to Blake 3 hash of `current_sk` Verifying key. This hash becomes and is used as Identity identifier.
In addition - `civilization` of this first `Iml` is always set to 0.
As an OPTION - `Attachments` can be added to this `Iml` and their `proof` put into `proof_of_attachments` field.
Inversion in Civilization 0 is never present.
As last step - `proof` is generated via signing `Iml` itself after serializing it into CBOR. Generated signature is attached into `proof` field.

### 2.2 Evolution

There are three types of Identifier evolution: Key evolution, Attachment evolution and Hybrid evolution.
As evolution is based on keys and attachments only - there is NO DIRECT NEED to store `Iml` as a file or DB entry. It can, and when possible - should, be re-evolved from Key Vault only.
Each evolution key SHOLD be tagged with `$IDENTIFIER_sk_$EVOLUTION` in the Key Vault, allowing implementation to easily collect Verifying keys per each evolution and construct key evolved `Iml`.
Re-evolving function should also take OPTIONAL set of `Attachment`s, verify their correctnest agains corresponding `parent` evolution and re-insert them, reconstructing full `Iml`.
Most attachments can be stored in their raw format in files with `.imla` (Inverted microledger attachment) extension, however, those which include Identifier related information SHOULD be stored
in encrypted format or on the secure storage, which is beyond this specification and can be determined by higher level application.
Storing `Iml` in file or database is allowed, aspecially on systems with limited hardware resources, but above security considerations apply.

#### 2.2.1 Key evolution

Whenever there is a suspicion that Signing key of previous civilization was exposed or there are other valid reasons to do so - evolution

In this case new `Iml` is created. It's `civilization` set to value of previous `Iml` increased by 1.
Next step is `next_sk` value of previous `Iml` is set to `current_sk` of this `Iml`, pairing Signing key for it is used later to finalize proof generation and signing of `Iml` itself.
New Key Pair should be generated and it's Verifying key set as `next_sk` value.
NO `id` value should be set.
Next, previous `Iml` should be serialized and operation output set as value for `inversion` property of current `Iml`.
Last step is to sign serialized and result of serialization should be signed by Signing key of `current_sk``s Signing key pair, and then set as value for `proof` property.

#### 2.2.2 Attachment evolution

Whenever there is a need to attach some data to be cryptographically bound to Identifier - it is done through Attachment evolution.

Prior to start the evolution, Attachment[s] should be created. Their `parent` field should be set to current `Iml` `civilization` increased by 1.
Next new `Iml` is created, it's `proof_of_attachments` set to signature of serialized set of `Attachment`s using `current_sk` (from previous non-empty `Iml`) key pair's Signing Key.
New `Iml`s `civilization` is set to previous value increased by 1.
`current_sk` and `next_sk` properties should be empty signalling that key from previous nearest non-empty `Iml` should be used.
Previous `Iml` serialized and set as `inversion` value. 
Using previous, valid `current_sk` new `Iml`s serialized data is signed and set as `proof` field value.

#### 2.2.3 Hybrid evolution

Is combination of both "Key evolution" and "Attachment evolution".
This type of evolution will step keys and add attachments to new `Iml`, use new key to sign them and include previous civilizations into new `Iml`, which becomes nev valid one.

In this scenario keys used for signing both `Attachment`s and new `Iml` are those set into new one according to steps form 2.2.1.
All other steps remain same.

### 2.3 Verification / validation

Verification of integrity if Identifier's `Iml` is done recursively from newest `Iml` to oldest, which contains `id` property.
Terms of integrity of `Iml` are next:
* All `civilization` values go from N to 0 decreasing by 1.
* All `next_sk` from `civilization` previous to validated matches `current_sk`.
* `proof` signature matches the one newly generated on serialized `Iml` itself.
* If any attachments present - their signatures should be verified and `parent` should match current `civilization` value.

Steps should be repeated on previous deserialized `Iml` from `inversion` property until `civilization` 0 is reached and validated.

If all `Iml`s pass verification process - Identifier is considered valid and it's source verified.

NOTE: To prevent post-evolution set of attacks, verifiers who already interacted with IML of Identity should store and check it's `civilization` level to match or be greater on each interaction.

### 2.4 Attachments

Attachments are not taking direct part in Identity's verification process. Thus are not required to be attached to `Iml` on each interaction.
However, it is a great way to share information, such as media, Verifiable Credentials, DID Document etc. Application should provide means to
 select which attachments to share or attach new data with "Attachment evolution" and include them into interaction `Iml`.

On the other side - if `Iml` which includes `Attachment`s signature, was already shared with peer - sharing attachments separately is enough
to have verification and validation in place.

#### 2.4.1 Data validity

As both `Iml` and `Attachment`s have two-way linkage and `proof` of both is generated using same key - data integrity and verification are given.

### 2.6 Identifier discontinuation

TBD

## 3. Interactions

Interactions between peers using `Iml` are intended to be peer-to-peer relationship. However, use of mediators is allowed, as interaction `Iml` is peer-to-peer encrypted.

To prepare interaction `Iml`, Identity holder creates new `Iml` with `civilization` set to any value. It is recommended to use random value.
Next, new EphemeralKey is generated and used to generate SharedSecret key with destination's peer's Public key.
Generated shared secret is used to encrypt serialized, and pre-populated with attachments if needed, Identifier's full `Iml` and then set as `inversion` value.
Value of PublicKey is set into `interaction_key` property as raw bytes set.
`id` property shoed be set to identify recipient's key used for SharedSecret generation. This usually should represent just key id - not 
Identifier, unless it's a public service with published DID to prevent peer's Identity reveal.

When above steps are completed, new interaction `Iml` is serialized, then BASE64_URL encoded and deflated using DEFLATE algorithm.

Recipient performs above steps in reverse and then runs "Verification / validation" recursion to establish state of the `Iml` and get it's Identity.
Recipient may then choose to continue interaction or not, based on application requirements, which are beyond this spec.
In addition, if Recipient already interacted with given Identifier before - it should verify that latest `civilization` is not lower than the highest
of previous interactions.

### 3.1 Interactions with non-Iml identities

TBD - should be pretty much the same

## 4. `did:iml`

DID:IML is unique in all the aspects. Unlike other DID methods - it does not have Identifier data in it's URL.
Instead, as identifier, result of interaction `Iml` is set. This approach is not only preventing linkage correlation, but as new EphemeralKey and, possibly, 
different recipient's key id used on each interaction - encoded string will always be different, so only repetitive part would be "did:iml:".

### 4.1 Examples

* Civilization 0 `Iml` interaction did:iml:
```
did:iml:pWxjaXZpbGl6YXRpb24BamN1cnJlbnRfc2uYQQQYphiLGDgYwBguGFYY4xiZGKcYahhrGGgYIRiyGKUYORhlGG4YSBjKGGYY-hhIGL0YXxi3EhicGDkYxhhCGLMYshgaGFsY7hivGCYYigcYMBjpGMQY-hhBGLIYjQMYphEY0xhzGEUYbhAY8BjBGDYCGCYYcBjhAxhOZ25leHRfc2uYQQQYoBiTGOQIGEEYoBgwGOYY3xj4GFgYoBg6GCEYuxhsGFYYZxiKGIgYKRizGNQY3hhVGFIYphi0GOsUBRh3GKEYhxhQGFwYmBijGC4YThiKGCsYqBjHGNIYlBhIGKEYRBcYGRiHGFwYsBgpGPQYQgIY5QQYGxgmGCQYYGlpbnZlcnNpb26ZAeQYpRhiGGkYZBh4GEAYORg4GDAYZRgyGDEYZRhiGDIYNRgxGDMYMBhlGDcYMxhlGGEYNBhmGDYYMhhlGGQYZRhmGDYYNRhiGGMYMxg1GDQYMBg2GDIYNRg0GGUYORg4GGUYORg2GGQYNRgyGDEYMhgxGDAYYhhmGDUYYxgxGDIYMhg5GDAYZBhkGGYYYRhsGGMYaRh2GGkYbBhpGHoYYRh0GGkYbxhuABhqGGMYdRhyGHIYZRhuGHQYXxhzGGsYmBhBBBgYGOcIGBgYuhgYGCcYGBitERgYGDIYGBjxGBgYURgYGMYYGBhCGBgYyxgYGMEYGBggGBgYGxgYGF8YGBjOGBgYrBgYGIgYGBiJGBgY5xgYGPwYGBhAGBgYzRgYGCEYGBgiGBgYmRgYGP4YGBi6GBgYPxgYGHgYGBhuGBgYkhgYGL0YGBifGBgYzRgYGPQYGBjiGBgYohgYGPcYGBj1GBgYZxgYGFwYGBibGBgYIhgYGPUYGBg7GBgYQhgYGGoYGBjpGBgY7AYYGBiLGBgY4BgYGPkYGBjjDBgYGDIYGBhhGBgY0BgYGCUYGBiDGBgYUxgYGJ0YZxhuGGUYeBh0GF8YcxhrGJgYQQQYGBimGBgYixgYGDgYGBjAGBgYLhgYGFYYGBjjGBgYmRgYGKcYGBhqGBgYaxgYGGgYGBghGBgYshgYGKUYGBg5GBgYZRgYGG4YGBhIGBgYyhgYGGYYGBj6GBgYSBgYGL0YGBhfGBgYtxIYGBicGBgYORgYGMYYGBhCGBgYsxgYGLIYGBgaGBgYWxgYGO4YGBivGBgYJhgYGIoHGBgYMBgYGOkYGBjEGBgY-hgYGEEYGBiyGBgYjQMYGBimERgYGNMYGBhzGBgYRRgYGG4QGBgY8BgYGMEYGBg2AhgYGCYYGBhwGBgY4QMYGBhOGGUYcBhyGG8YbxhmGJgYQBgYGHYYGBjFGBgYZxgYGEsYGBg0GBgYiwwYGBh7GBgYiQsYGBgZGBgYzhgYGFsYGBjxGBgYzhIYGBi8GBgYhBgYGL4YGBiFGBgYixgYGIUYGBg5GBgYQxgYGEYYGBgqFhgYGMMYGBgwGBgYURgYGJIYGBheGBgY5BgYGPUGGBgYaBgYGEUYGBhrGBgYiBgYGMMYGBhKGBgYUhgYGDAYGBgmGBgYcxgYGHwYGBjxGBgYGRgYGOMMGBgYyRgYGCYYGBi9GBgYQRgYGKUYGBjLGBgYPRgYGCoYGBi7GBgYJxgYGK8YGBj7GBgYQhgYGOJlcHJvb2aYQBiUGPYYoBihAgAYghjyGMkYnAMYLhg2GJ0YHBivGPUY8RhtGPAY-RitGPEY9RiZGFgY3RiRGJoYjxgdGCIYphiPGNwYUBijGJEYnRhLBwcYyxi8GI4YgBinGJUYpxgbGH4YMBh0FxhJGFIYYxjvGFwSGP8YqAEY6Q
```

* Multiple evolutions `Iml` interaction did:iml:
```
did:iml:pWxjaXZpbGl6YXRpb24CamN1cnJlbnRfc2uYQQQYoBiTGOQIGEEYoBgwGOYY3xj4GFgYoBg6GCEYuxhsGFYYZxiKGIgYKRizGNQY3hhVGFIYphi0GOsUBRh3GKEYhxhQGFwYmBijGC4YThiKGCsYqBjHGNIYlBhIGKEYRBcYGRiHGFwYsBgpGPQYQgIY5QQYGxgmGCQYYGduZXh0X3NrmEEEGBwYwhhqGOcYKhjGGHYYeBibGMQY3RiGGCQYJRiHFhiiGJUYyBhyGI4Y2hiKGH4Y1RijGF8Y9xjJAxi7GPsYYgEY-hjoGMwYPRhYGDEYzRiSGOcYnxgsGPgYJRjkGLgLGGYYkQMY5himGDcYzBjKGIcYohhrGEAYKRhnaWludmVyc2lvbpkFXBilGGwYYxhpGHYYaRhsGGkYehhhGHQYaRhvGG4BGGoYYxh1GHIYchhlGG4YdBhfGHMYaxiYGEEEGBgYphgYGIsYGBg4GBgYwBgYGC4YGBhWGBgY4xgYGJkYGBinGBgYahgYGGsYGBhoGBgYIRgYGLIYGBilGBgYORgYGGUYGBhuGBgYSBgYGMoYGBhmGBgY-hgYGEgYGBi9GBgYXxgYGLcSGBgYnBgYGDkYGBjGGBgYQhgYGLMYGBiyGBgYGhgYGFsYGBjuGBgYrxgYGCYYGBiKBxgYGDAYGBjpGBgYxBgYGPoYGBhBGBgYshgYGI0DGBgYphEYGBjTGBgYcxgYGEUYGBhuEBgYGPAYGBjBGBgYNgIYGBgmGBgYcBgYGOEDGBgYThhnGG4YZRh4GHQYXxhzGGsYmBhBBBgYGKAYGBiTGBgY5AgYGBhBGBgYoBgYGDAYGBjmGBgY3xgYGPgYGBhYGBgYoBgYGDoYGBghGBgYuxgYGGwYGBhWGBgYZxgYGIoYGBiIGBgYKRgYGLMYGBjUGBgY3hgYGFUYGBhSGBgYphgYGLQYGBjrFAUYGBh3GBgYoRgYGIcYGBhQGBgYXBgYGJgYGBijGBgYLhgYGE4YGBiKGBgYKxgYGKgYGBjHGBgY0hgYGJQYGBhIGBgYoRgYGEQXGBgYGRgYGIcYGBhcGBgYsBgYGCkYGBj0GBgYQgIYGBjlBBgYGBsYGBgmGBgYJBgYGGAYaRhpGG4YdhhlGHIYcxhpGG8YbhiZARjkGBgYpRgYGGIYGBhpGBgYZBgYGHgYGBhAGBgYORgYGDgYGBgwGBgYZRgYGDIYGBgxGBgYZRgYGGIYGBgyGBgYNRgYGDEYGBgzGBgYMBgYGGUYGBg3GBgYMxgYGGUYGBhhGBgYNBgYGGYYGBg2GBgYMhgYGGUYGBhkGBgYZRgYGGYYGBg2GBgYNRgYGGIYGBhjGBgYMxgYGDUYGBg0GBgYMBgYGDYYGBgyGBgYNRgYGDQYGBhlGBgYORgYGDgYGBhlGBgYORgYGDYYGBhkGBgYNRgYGDIYGBgxGBgYMhgYGDEYGBgwGBgYYhgYGGYYGBg1GBgYYxgYGDEYGBgyGBgYMhgYGDkYGBgwGBgYZBgYGGQYGBhmGBgYYRgYGGwYGBhjGBgYaRgYGHYYGBhpGBgYbBgYGGkYGBh6GBgYYRgYGHQYGBhpGBgYbxgYGG4AGBgYahgYGGMYGBh1GBgYchgYGHIYGBhlGBgYbhgYGHQYGBhfGBgYcxgYGGsYGBiYGBgYQQQYGBgYGBgY5wgYGBgYGBgYuhgYGBgYGBgnGBgYGBgYGK0RGBgYGBgYGDIYGBgYGBgY8RgYGBgYGBhRGBgYGBgYGMYYGBgYGBgYQhgYGBgYGBjLGBgYGBgYGMEYGBgYGBgYIBgYGBgYGBgbGBgYGBgYGF8YGBgYGBgYzhgYGBgYGBisGBgYGBgYGIgYGBgYGBgYiRgYGBgYGBjnGBgYGBgYGPwYGBgYGBgYQBgYGBgYGBjNGBgYGBgYGCEYGBgYGBgYIhgYGBgYGBiZGBgYGBgYGP4YGBgYGBgYuhgYGBgYGBg_GBgYGBgYGHgYGBgYGBgYbhgYGBgYGBiSGBgYGBgYGL0YGBgYGBgYnxgYGBgYGBjNGBgYGBgYGPQYGBgYGBgY4hgYGBgYGBiiGBgYGBgYGPcYGBgYGBgY9RgYGBgYGBhnGBgYGBgYGFwYGBgYGBgYmxgYGBgYGBgiGBgYGBgYGPUYGBgYGBgYOxgYGBgYGBhCGBgYGBgYGGoYGBgYGBgY6RgYGBgYGBjsBhgYGBgYGBiLGBgYGBgYGOAYGBgYGBgY-RgYGBgYGBjjDBgYGBgYGBgyGBgYGBgYGGEYGBgYGBgY0BgYGBgYGBglGBgYGBgYGIMYGBgYGBgYUxgYGBgYGBidGBgYZxgYGG4YGBhlGBgYeBgYGHQYGBhfGBgYcxgYGGsYGBiYGBgYQQQYGBgYGBgYphgYGBgYGBiLGBgYGBgYGDgYGBgYGBgYwBgYGBgYGBguGBgYGBgYGFYYGBgYGBgY4xgYGBgYGBiZGBgYGBgYGKcYGBgYGBgYahgYGBgYGBhrGBgYGBgYGGgYGBgYGBgYIRgYGBgYGBiyGBgYGBgYGKUYGBgYGBgYORgYGBgYGBhlGBgYGBgYGG4YGBgYGBgYSBgYGBgYGBjKGBgYGBgYGGYYGBgYGBgY-hgYGBgYGBhIGBgYGBgYGL0YGBgYGBgYXxgYGBgYGBi3EhgYGBgYGBicGBgYGBgYGDkYGBgYGBgYxhgYGBgYGBhCGBgYGBgYGLMYGBgYGBgYshgYGBgYGBgaGBgYGBgYGFsYGBgYGBgY7hgYGBgYGBivGBgYGBgYGCYYGBgYGBgYigcYGBgYGBgYMBgYGBgYGBjpGBgYGBgYGMQYGBgYGBgY-hgYGBgYGBhBGBgYGBgYGLIYGBgYGBgYjQMYGBgYGBgYphEYGBgYGBgY0xgYGBgYGBhzGBgYGBgYGEUYGBgYGBgYbhAYGBgYGBgY8BgYGBgYGBjBGBgYGBgYGDYCGBgYGBgYGCYYGBgYGBgYcBgYGBgYGBjhAxgYGBgYGBhOGBgYZRgYGHAYGBhyGBgYbxgYGG8YGBhmGBgYmBgYGEAYGBgYGBgYdhgYGBgYGBjFGBgYGBgYGGcYGBgYGBgYSxgYGBgYGBg0GBgYGBgYGIsMGBgYGBgYGHsYGBgYGBgYiQsYGBgYGBgYGRgYGBgYGBjOGBgYGBgYGFsYGBgYGBgY8RgYGBgYGBjOEhgYGBgYGBi8GBgYGBgYGIQYGBgYGBgYvhgYGBgYGBiFGBgYGBgYGIsYGBgYGBgYhRgYGBgYGBg5GBgYGBgYGEMYGBgYGBgYRhgYGBgYGBgqFhgYGBgYGBjDGBgYGBgYGDAYGBgYGBgYURgYGBgYGBiSGBgYGBgYGF4YGBgYGBgY5BgYGBgYGBj1BhgYGBgYGBhoGBgYGBgYGEUYGBgYGBgYaxgYGBgYGBiIGBgYGBgYGMMYGBgYGBgYShgYGBgYGBhSGBgYGBgYGDAYGBgYGBgYJhgYGBgYGBhzGBgYGBgYGHwYGBgYGBgY8RgYGBgYGBgZGBgYGBgYGOMMGBgYGBgYGMkYGBgYGBgYJhgYGBgYGBi9GBgYGBgYGEEYGBgYGBgYpRgYGBgYGBjLGBgYGBgYGD0YGBgYGBgYKhgYGBgYGBi7GBgYGBgYGCcYGBgYGBgYrxgYGBgYGBj7GBgYGBgYGEIYGBgYGBgY4hhlGHAYchhvGG8YZhiYGEAYGBiUGBgY9hgYGKAYGBihAgAYGBiCGBgY8hgYGMkYGBicAxgYGC4YGBg2GBgYnRgYGBwYGBivGBgY9RgYGPEYGBhtGBgY8BgYGPkYGBitGBgY8RgYGPUYGBiZGBgYWBgYGN0YGBiRGBgYmhgYGI8YGBgdGBgYIhgYGKYYGBiPGBgY3BgYGFAYGBijGBgYkRgYGJ0YGBhLBwcYGBjLGBgYvBgYGI4YGBiAGBgYpxgYGJUYGBinGBgYGxgYGH4YGBgwGBgYdBcYGBhJGBgYUhgYGGMYGBjvGBgYXBIYGBj_GBgYqAEYGBjpZXByb29mmEAYUBhGGHQYMxjODRjoGFEYxRhYGJQYtxi9GEYYQhiKGCQYwRj4GBoYdRgqGNAYjBhLGFYY7xjxGGgYJRjYAxhrGJoYoBjrGHkYkhggGPUY1BjIBhjfGM0Y0hiPGGoYeBAY3g0YzBgZGFsYnRcYbBibGBsY5Bg2GEgYMQ
```

Note: Pre-compressed, serialized `Iml`s may get quite big, but after compression is done - their size is reduced by 99% (unless some specific attachments are present);
This is still producing DID URLs of significant length (from 16kb of civilization 0 to 140kb for civilization 10 with key evolutions). Considering all the benefits - such
size is not relevant, however deflation and `Iml` size decrease proposals are highly welcome at this stage.

### 4.2 DID Document attaching, updating and resolution

TBD

### `did:iml` and DIDComm v2

TBD

# License

[Apache 2.0](LICENSE)

