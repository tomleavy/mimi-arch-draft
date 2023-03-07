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

In order to achieve cross-application federation between a set of MLS
applications there must be a common set of APIs available that implement the
basic AS/DS requirements as defined by `MLS Architecture`. To facilitate the
creation of groups asynchronously, MLS clients may have a need to establish 
identity, credentials and a queue of key packages. Once groups are established,
it is useful for clients to have access to a common repository for welcome
messages, pending proposals, commit messages, and ratchet trees. 

In this document we describe a MIMI Gateway API that can be used to provide 
intra domain and cross domain federation between MLS applications.

# Operational Context 

A basic federation scenario consists of a bi-directional data flow between
three types of actors: clients, application servers and MIMI gateways. Clients
communicate with application servers, application servers communicate with
gateway services, and gateway services communicate with other gateway services.

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

The MIMI Gateway is designed to be a hybrid of AS and DS functionality as
defined by `MLS Architecture`. It has an internal interface for
applications within its domain to federate with each other, as well as an
external interface that allows for cross-domain federation. A gateway acts as a
permissioned database of the following information:

* Unique identifiers of clients that can be queried by application-defined tags.
* Queryable queues of MLS Key Packages indexed by identifier, protocol version,
cipher suite and a custom label.
* MLS proposals, commits, welcome messages and ratchet trees indexed by MLS
`group_id` and `epoch_id`.

## Identity Providers

An identity provider helps ensure a consistent AS behavior between federating
MLS applications. Internally an identity provider MUST implement the following
set of functionality. 

* Declare support for a specific set of MLS credential types.
* Validate an identity based on its public key, credential, the current set of
  group context extensions, and opaque application context. If validation is
  done in the context of a commit, group context extensions MUST include any
  changes due to a GroupContextExtensions proposal.
* Uniquely identify a client based on its identity to ensure that the same
  identity is not added to a MLS group multiple times.
* Determine if one identity is a valid successor of another in order to verify
  if an Update proposal, or a remove proposal within an external commit should
  be allowed. Unless otherwise specified, a client is a valid successor of
  another client if their client identifiers are equal.

An example interface of an identity provider is as follows:

~~~
struct {
    HPKEPublicKey public_key;
    Credential credential;
} Identity;

struct {
    opaque context<V>
} ApplicationContext;

interface {
    fn supported_credentials() -> [CredentialType];

    fn validate(Identity identity, Extension group_context_ext[],
        ApplicationContext a_ctx) -> bool;

    fn client_identifier(Identity identity) -> Vec<u8>;

    fn valid_successor(Identity predecessor, Identity successor) -> bool {
        return self.client_identifier(predecessor) == 
            self.client_identifier(successor);
    }
} IdentityProvider;
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
   uint64 msg_timestamp;
} X509ApplicationContext;

struct {
    X509IdentityRange range;
} X509Parameters;
~~~

### X.509 Identifiers

Calculating a client's identifier is done by iterating through a subset of X.509
subject fields found within the client's certificate chain. The range of
certificates in the chain to reference as part of the calculation is defined as
starting with `start` values from the leaf and ending with
`end` values from the leaf. A single unique identifier is calculated by
hashing the Common Name value found in each certificate within the reference
range using the current group's ciphersuite hash function.

~~~
struct {
   uint8 start;
   uint8 end<0..255>;
} X509IdentityRange;

fn client_identifier(HashFunction hasher, CertificateChain cert_chain,
X509IdentityRange range)
{
    for certificate in cert_chain[range.start..=range.end] {
        let common_name = certificate.subject.common_name;

        if (!common_name) {
            throw "Common name is required";
        }

        hasher.update(common_name);
    }

    return hasher.finalize();
}
~~~

### Handing Timestamps 

// TODO: Utilize X509ApplicationContext in order to set a msg_timestamp that
will be used to determine if the certificate chain was valid at a specific time
of use. 

// TODO: Describe how to check for expired certificates at commit time and
propose their removal. Other clients / Server MUST verify this has been done
based on the timestamp of the message assigned by the server and reject
accordingly.

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
the client with the identity service using the following request:

~~~
HTTP POST /apps/{appId}/clients 

Input:

{
    clientIdentity: Base64(IdentityProvider.client_identity),
    tags: [String]
}

Output:

{
    clientId: UUIDv4
}

~~~

In the above figure, the returned `clientId` is the new unique
identifier assigned to the client by the identity service. Services MUST ensure
that `clientIdentity` is unique amongst all registered clients. 

A client MAY be editable by the following request:

~~~
HTTP PATCH /apps/{appId}/clients/{clientId}

Input:

{
   clientIdentity: Blob,
   tagsToAdd: Tags,
   tagsToRemove: Tags
}
~~~

Patching an existing client MUST fail if changing `clientIdentity` results in a
conflict with another existing client.

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
