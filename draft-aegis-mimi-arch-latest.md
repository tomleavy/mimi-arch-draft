---
title: More Instant Messaging Interoperability (MIMI) Back-end Architecture
abbrev: MIMI Architecture
docname: draft-aegis-mimi-arch-latest
category: std

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  fullname: Joel ALwen
    organization: Amazon - Wickr
    email: alwenjo@amazon.com

 -  fullname: Tom Leavy
    organization: Amazon - Wickr
    email: tomleavy@amazon.com 

 -  fullname: Marta Mularczyk
    organization: Amazon - Wickr
    email: mulmarta@amazon.com

contributor:

informative:


--- abstract

TODO Abstract


--- middle

# Glossary

* client -- as in MLS RFC
* UUID

# Introduction

In order to achieve cross-application federation between a set of MLS applications there must be a common set of APIs available that implement the basic AS/DS requirements as defined by `MLS Architecture`. To facilitate the creation of groups asynchronously, MLS clients may have a need to establish identity, credentials and a queue of key packages. Once groups are established, it is useful for clients to have access to a common repository for welcome messages, pending proposals, commit messages, and ratchet trees. 

In this document we describe a MIMI Gateway API that can be used to provide intra domain and cross domain federation between MLS applications.

# Operational Context 

A basic federation scenario consists of a bi-directional data flow between actors. Clients
communicate with application servers, application servers
communicate with gateway services, and gateway services
communicate with other gateway services.

~~~
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
'                       Domain A                                '
'                                                               '
' +-------+     +----------------------+     +----------------+ '
' | Alice | --- | Application Server 1 | --- | MIMI Gateway A |-'-----+
' +-------+     +----------------------+     +----------------+ '     |
' +-------+     +----------------------+       |                '     |
' |  Bob  | --- | Application Server 2 |-------+                '     |
' +-------+     +----------------------+                        '     |
'                                                               '     |
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +     |
                                                                      |
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +     |
'                       Domain B                                '     |
'                                                               '     |
' +-------+     +----------------------+     +----------------+ '     |
' | Carol | --- | Application Server 3 | --- | MIMI Gateway B |-'-----+ 
' +-------+     +----------------------+     +----------------+ '
' +-------+     +----------------------+       |                '
' | Dave  | --- | Application Server 4 |-------+                '
' +-------+     +----------------------+                        '
'                                                               '
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
~~~

# Gateway Overview

The MIMI Gateway is designed to be a hybrid of AS and DS functionality has
defined by `MLS Architecture`. It has an internal interface for
applications within its domain to federate with each other, as well as an
external interface that allows for cross-domain federation. A gateway acts as a
permissioned database of the following information:

* Unique identities that can be grouped by tags.
* Queryable queues of MLS Key Packages indexed by identity, protocol version, cipher suite, custom labels.
* MLS Group proposals, commits, welcome messages and ratchet trees indexed by epoch.

## Identity Providers

An identity provider helps ensure a consistent AS behavior between federating
MLS applications. Internally an identity provider MUST implement the following
set of functionality. 

* Declare support for a specific set of MLS credential types.
* Validate a credential given a public key that is stored along side that
  credential in an MLS Leaf and a timestamp that can be used to determine
  validity of credentials that may expire (Ex. X509 Certificate credentials).
* Uniquely identify a Leaf based on its identity to ensure that the same
  identity is not added to a MLS group multiple times.
* Uniquely identity the entity that controls a specific leaf.
* Determine if an identity is controlled by the same entity as another identity.

An example interface of an identity provider is as follows:

~~~
struct {
    HPKEPublicKey public_key;
    Credential credential;
} Identity;

fn supported_credentials() -> [CredentialType];
fn validate(Identity identity, u64 time) -> bool;
fn leaf_identifier(Identity identity) -> Vec<u8>;
fn entity_identifier(Identity identity) -> Vec<u8>;

fn valid_successor(Identity predecessor, Identity successor) -> bool {
    return self.entity_identifier(predecessor) == self.entity_identifier(successor);
}
~~~

Each identity provider has a unique value that identifies its behavior along
with opaque parameters that help synchronize various options across
applications. 

~~~
uint16 IdentityProviderType;

struct {
    IdentityProviderType type;
    opaque parameters<V>;
} IdentityConfiguration;
~~~

## Basic Identity Provider 

The basic identity provider is the minimal implementation of an identity
provider. It has the following properties:

* Basic is the only type of credential that is supported.
* Credentials are always valid.
* Leaf and entity identifiers are equal to the bare assertion of identity
  provided by a BasicCredential.

## X.509 Identity Provider

The X.509 identify provider allows for a hierarchical identity that is based
upon a certificate chain. x509 is the only credential type supported.
Certificate chains MUST be validated according to the rules in RFC 5280 using
the trust roots agreed upon by the (TODO: Some sort of extension dealing with
trust root negotiation).

~~~
struct {
   int leaf_offset;
   int entity_offset;
} X509Parameters;
~~~

### X.509 Identifiers

Leaf identifiers in an X.509 Identity provider are based upon a certificate's subject.
The certificate that is `leaf_offset` certificates away from the leaf should be
used for leaf identification purposes, with a `leaf_offset` of 0 representing the
leaf certificate itself. If a CN value is found within the certificate's subject,
then it's DER representation should be used as a leaf identifier. If a CN value
is not found, then the DER representation of the entire subject should be used in its
place.

Similarly, `entity_offset` is used to determine an entity identifier following
the same process.

## Applications

A gateway can manage information for multiple applications that may or may not
federate with each other. An application is uniquely identified by a unique
ApplicationID and is specified as:

~~~
struct {
    UUIDv4 id;
} ApplicationId;
~~~

~~~
struct {
    ApplicationId: id;
    IdentityConfiguration identity_configuration;
    // TODO: Other stuff???
} ApplicationConfiguration;
~~~

An application MUST be configured with an IdentityProvider that matches all of
the other applications that it needs to federate with to ensure
interoperability.

# Managing Identities

Each gateway implements client discovery. It assigns to each
registered client a unique identifier (a UUID), which remains constant
for as long as the client uses the system. In contrast, a client's
_identity_ may change (for instance, if they change phone number).
Further, each client is (optionally) assigned a set of tags. Each tag
represents a grouping of clients, for example:
1. A tag `account_id:alice@org` represents all clients belonging to an
   account `alice@org`.
2. Tags `moderator` or `clearance:top_secret` represent all clients with
   given access rights.

Tags of a given client are provided by the application. The service
allows the application to search for clients by tags. For example,
searching by tag 1. above allows to list all clients owned by
`alice@org`, which is a typical scenario in messaging applications where
Bob invites a multi-device account of Alice. Searching by a tag 2.
above allows to add an arbitrary moderator, or all clients owned by
entities with the right clearance.

## Identity Registration
When a client registers with an application, the application registers
the client with the identity service using the following query:

// TODO: This should be described as an HTTP route.

~~~
u16 IdentityQueryType = 1;

struct {
    opaque entity_identifier<V>;
    opaque tag<V>;
} RegisterIdentityQuery;
~~~

In the above figure, the returned `client_id` is the new unique
identifier assigned to the client by the identity service.

## Discovering Clients

## Retrieving Identities

## Updating and Unregistering Clients

Define the interface.

# Key Pool Service

Define the interface.

# Group State Service

Define the interface.

# Example Usage

1. Defining an application
2. Creating / managing identities
3. Creating / managing key pools
4. Fetching keys from key pools
5. Creating a group
6. Joining a group
7. Sending commits






# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

## Gateway Access 

As shown in Figure 1, MIMI Gateways present two interfaces. An internal
interface that gives application servers write access, and an external interface that gives other
Gateways read access. MLS clients MUST NOT have direct read or write access to a
gateway, and instead communicate with the gateway through their application
server. Application servers MUST NOT have write access to data owned by other
applications. 

## Gateway Authentication 

// TODO: How should we add auth so that gateways aren't always completely open
to the internet.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

---
