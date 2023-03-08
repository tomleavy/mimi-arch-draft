---
title: More Instant Messaging Interoperability (MIMI) Back-end Architecture
abbrev: MIMI Architecture
docname: draft-aegis-mimi-arch-latest
category: std
submissionType: IETF

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

    fn client_handle(Identity identity) -> Vec<u8>;

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

Identifiers (e.g. handles for clients) are derived by iterating through a subset
of X.509 subject Common Name fields found within the client's certificate chain.
Common Name fields MUST not contain any of the 5 special characters "@", "/",
"#", "$" and ":". The range of certificates in the chain to used in the
derivation is defined as starting with `start` values from the leaf and ending
with `end` values from the leaf.

~~~
fn identifier(CertificateChain cert_chain, uint8 start, uint8 end) {
    string id = new String;
    bool first = true;
    
    for certificate in cert_chain[start...end] {
        let common_name = certificate.subject.common_name;

        if (!common_name) {
            throw "Common name is required";
        }
        
        if (common_name.contains("@","/","#","$",":") {
            throw "Common names may not contain @/#$: characters.";
        }

        if (!first) {
            id.append(":");
        } else {
            first = false;
        }
        id.append(common_name);
    }

    return id;
}
~~~

### X.509 Client Handles
A client handle is a human readable name for a client.
{{?I-D.draft-mahy-mimi-identity}} The X.509 identity provider extracts the
client handle from a client's credentials by fixing a range and calling
'identifier' for the certificates in the range.

{{?I-D.ietf-mls-protocol}}

~~~
struct {
    uint8 start;
    uint8 end<0...255>;
} X509ClientHandleRange

fn client_handle(CertificateChain cert_chain, X509ClientHandleRange range) {
    return identifier(cert_chain, range.start, range.end)
}
~~~

### X.509 Account Identifiers

Many messaging systems use of multi-client (e.g. multi-device) accounts.
Accounts are also refered to as users {{?I-D.draft-mahy-mimi-identity}}. Account
handles are calculated like client handles but based on the certificate
at the Account Handle offset (instead of Client Handle range).

~~~
uint8 X509AcntHandleOffset;

fn acount_identifier(CertificateChain cert_chain, X509AcntHandleOffset offset) {
    return identifier(cert_chain, offset, offset)
}
~~~

The Account Handle offset strictly succeeds the Client Handle range in the
certificate chain counting from the leaf certificate up.

~~~
X509AcntHandleOffset > X509ClientHandleRange.end
~~~~

### X.509 Domains Names

Federated messaging systems often associate accounts with a domain (e.g. that of
a home server hosting the account). Domain Names are calculated just like
Account Handles but using the Domain Name offset in place of the Account
Handle offset.

~~~
uint8 X509DomainNameOffset;

fn domain_identifier(CertificateChain cert_chain, X509DomainNameOffset offset) {
    return identifier(cert_chain, offset, offset)
}
~~~

The Domain Name offset strictly succeeds the Client Handle range in the
certificate chain counting from the leaf certificate up.

~~~
X509DomainIDOffset > X509ClientHandleRange.end
~~~~

When Account identifiers are used then the Domain Name offset must also
strictly succeed the Account Handle offset.

~~~
X509DomainIDOffset > X509AccountIDRange.end
~~~~


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
_handle_ may change (for instance, if they change a phone's hostname).
Further, each client is (optionally) assigned a set of tags. Each tag
represents attributes associated with the client, for example:
1. A tag `account_id:alice@org` indicates the client belongs to the (domain
   scoped) account `alice@org`.
2. Tags `moderator` or `clearance:top_secret` indicates the clients have certain
   roles or access rights.

Tags of a given client are provided by the application. The service
allows the application to search for clients by tags. For example,
searching by tag 1. above allows to list all clients owned by
`alice@org`, which is a typical scenario in messaging applications where
Bob invites a multi-device account of Alice to join a chat. Searching by a tag 
2. above allows to add an arbitrary moderator, or all clients owned by
entities with the right clearance.

## Identity Registration

When a client registers with an application, the application registers
the client with the identity service using the following request:

~~~
HTTP POST /apps/{appId}/clients 

Input:

{
    ClientHandle: Base64(IdentityProvider.client_handle),
    tags: [String]
}

Output:

{
    clientId: UUIDv4
}

~~~

In the above figure, the returned `clientId` is the new identifier assigned to
the client by the identity service. Services MUST ensure that `clientId` is
unique amongst all registered clients. 

A client MAY be editable by the following request:

~~~
HTTP PATCH /apps/{appId}/clients/{clientId}

Input:

{
   ClientHandle: Base64(IdentityProvider.client_identity),
   tagsToAdd: [String],
   tagsToRemove: [String]
}
~~~

Patching an existing client MUST fail if changing `ClientHandle` results in a
conflict with another existing client.

## Client Discovery

An application can list identifiers of all clients with a given
tag using the following request:

~~~
HTTP GET /apps/{appId}/clients 

Input:

{
    tag: String
}

Output:

{
    identities: [
        {
            clientId: UUIDv4,
            clientIdentity: Base64(IdentityProvider.client_identity),
            tags: [String]
        },
    ...
    ]
}

~~~

## Identity Retrieval

TODO

## Identity Deletion

TODO

# Managing Key Packages

Each gateway implements a directory providing MLS key packages, which contain
initial keying material of clients and can be used to add them to the group
even when they are offline.

Key packages are collected into _key pools_ of packages with common attributes.
In particular, all key packages in a key pool belong to the same client and use
the same cipher suite and protocol version. In addition, an application can
define a custom label for key pools, for example, on that specifies custom MLS
extensions clients must support.

When a client is added to an MLS group (typically after being discovered as
described in {{client-discovery}}), the application (or a gateway in case of
federation) requests a key package from one of the client's pools with
attributes matching those used by the group. By default, the returned key
package is immediately deleted, in order to avoid key material reuse across
groups. To improve availability in situations where key pools may get depleted,
a gateway MAY provide an option to support so-called final keys, i.e., a key
pool can have one final key package that can be used multiple times but only
after all other key packages are used up. However, this MUST come with a
security warning.

## Key Pool Creation

A gateway MUST support key pool creation with the following request:

~~~
HTTP POST /apps/{appId}/clients/{clientId}/pools 

Input:

{
    protocolVersion: uint16,
    cipherSuite: uint16,
    appLabel: String
}

Output:

{
    keyPoolId: UUIDv4
}

~~~

If the above request is successful, a new key pool with unique identifier
`keyPoolId` and provided attributes is created. Note that the `clientId` and
`appId` are provided in the URI.

## Key Pool Update

A gateway MUST support updating the key packages in an existing pool using the
following request:

~~~
HTTP PATCH /apps/{appId}/clients/{clientId}/pools/{keyPoolId}

Input:

{
    keyPackages: [Base64(TLS-serialized MLSMessage)],
    isReset: bool
}

Output:

{
    keyPackagesInPool: uint
}
~~~

When processing the above request, a gateway SHOULD verify that each entry in
`keyPackages` contains an MLS key package that is valid according to 
{{?I-D.ietf-mls-protocol}}. If the above check fails, the request has no effect.

The request (if successful) results in the key pool `keyPoolId` (as in the URI)
being updated as follows:

1. If `isReset` is true, remove all key packages from the pool.
2. In any case, insert, all key packages from `keyPackages` to the pool.

The output of the request is the number of key packages in the pool after
update.

In addition, a gateway MAY support updating other key pool attributes. In this
case, the above input has additional optional fields:

~~~
Input:

{
    keyPackages: [Base64(TLS-serialized MLSMessage)],
    isReset: bool,
    appLabel: String,
    finalKey: Base64(TLS-serialized MLSMessage),
}
~~~

If provided, `appLabel` replaces the respective attribute of the key pool.
If the gateway supports final keys and `finalKey` is provided, the gateway
SHOULD verify that `finalKey` contains an MLS key package that is valid
according to {{?I-D.ietf-mls-protocol}}. The `finalKey` is stored for the given 
key pool, replacing the previously stored final key (if present).

## Key Package Retrieval

A gateway MUST allow an application or gateway to retrieve a key package of a
given client using the following request:

~~~
HTTP POST /apps/{appId}/clients/{clientId}/keyPackages

Input:

{
    protocolVersion: uint16,
    cipherSuite: uint16,
    appLabel: String  // TODO mark optional somehow
}

Output:

{
    keyPackage: [Base64(TLS-serialized MLSMessage)]
    isFinalKey: bool // TODO mark optional somehow
}
~~~

The above request has the following effect:

* An arbitrary key pool with attributes matching the provided `appId`,
  `clientId`, `protocolVersion`, `cipherSuite` and `appLabel` is chosen. If
  there is no such key pool, the request has no effect.
* If the above key pool contains (non-final) key packages, a key package from
  the pool is chosen (according to gatewey's policy), returned and deleted. The
  `isFinalKey` flag in the output is set to false. The returned key package MUST
  NOT be returned by any future fetch key package request.
* Else, if there is a final key stored for the key pool, the output contains
  this final key and the `isFinalKey` flag is set to true.
* Else, the request has no effect.

## Key Pool Deletion

TODO

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
