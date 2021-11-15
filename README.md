# IML - Inverted Microledger

## Abstract

IML (Inverted Microledger) is a variant of (Decentralized identifiers)[https://www.w3.org/TR/did-core/#dfn-decentralized-identifiers] and [DID Method](https://www.w3.org/TR/did-core/#dfn-did-methods) designed to provide highest level of security and privacy.
This document is and should be interpreted as DI/DID specifications until stated otherwise.

## Status

Both specifications and reference implementation (also part of this repository) are in draft state. Version of the draft is equal to crate version specified in Cargo.toml file.

## Copyright notice

Copyright (2021) Ivan Temchenko - until donated to proper governing foundation.

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

### 1.2 Cryptographical algorithms

IML uses (ECDSA/P256)[https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm] signatures for both `Iml` and `Attachment` `proof` generation.
For interactions `Iml` is encrypted using ephemeral Diffie-Hellman key exchanges with the secp256k1 elliptic curve.

### 1.3 IML Data Model

IML has main object named `Iml`, which is serializable. IML supperts (CBOR)[https://www.rfc-editor.org/rfc/rfc8949.html] serialization ONLY.
This is due to a fact that all properties are sets of raw bytes or guarranteed UTF-8 strings. In addition, during interaction, entire inner Iml of the envelope is deflated using DEFLATE algorithm to minimize data transfered over network.

IML uses recursion to provide consistent, uninterrupted chain of events, which is easy to parse and verify. Recursive property of `Iml` structure is named `inversion` and is OPTIONAL set of bytes produced from serializing previous Iml state.

`Iml` also have `id` property, which is OPTIONAL string value representing Identifier itself (present ONLY on civilization 0 and is Blake3 hash of initial signing key), or key reference when been sent to peer. In all other `Iml` civilization is absent.

Verifying key, which is pair of signing key used to `proof` sign current `Iml` is located as raw set of bytes under `current_sk` property.

Next commited verifying key, which is used during `evolution` is located as raw set of bytes under `next_sk` property.

`interaction_key` property is OPTIONAL, present and used only during interaction and contains PUBLIC (Encoded point) key of Identity holder's DH Secret key.

`civilization` property is used to indicate current level of `evolution` of identifier and is used to detect `degraded` attacks for known parties. unsigned 64 bit integer is used.

`attachments` property is OPTIONAL set of `Attachment`s.

`proof_of_attachment` is OPTIONAL set of bytes of the attachments signature and is used to validate attachments, which may be delivered separately from `Iml`;

`proof` is property of `Iml`, which is a set of bytes of signature generated from all non-OPTIONAL fields serialized as CBOR bytes.

#### 1.3.1 IML Attechment Data Model

'parent' - unsigned 64 bit integger of parent `Iml`s `civilization` property.

`payload` - set of bytes of any desired information;

`payload_type` - UTF-8 string indicating type of attached data. Reserved values apply.

`proof` - similar to `Iml`s proof - signature, generated from CBOR serialized data, using same key as for `parent` event signing.

### 2. Identifier Lifecycle

### 3. Interactions

### 4. `did:iml`

 