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

Many messaging systems use multi-client (e.g. multi-device) accounts.
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
    clientHandle: Base64(IdentityProvider.client_handle),
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
   clientHandle: Base64(IdentityProvider.client_handle),
   tagsToAdd: [String],
   tagsToRemove: [String]
}
~~~

Patching an existing client MUST fail if changing `clientHandle` results in a
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
            clientHandle: Base64(IdentityProvider.client_handle),
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

Key packages are collected into _key queues_ of packages with common attributes.
In particular, all key packages in a key queue belong to the same client and use
the same cipher suite and protocol version. In addition, an application can
define a custom label for key queues, for example, one that specifies custom MLS
extensions clients must support.

When a client is added to an MLS group (typically after being discovered as
described in {{client-discovery}}), the application (or a gateway in case of
federation) requests a key package from one of the client's queues with
attributes matching those used by the group. By default, the returned key
package is immediately deleted, in order to avoid key material reuse across
groups. To improve availability in situations where key queue may get depleted,
a gateway MAY provide an option to support so-called final keys, i.e., a key
queue can have one final key package that can be used multiple times but only
after all other key packages are used up. However, this MUST come with a
security warning.

## Key Queue Creation

A gateway MUST support key queue creation with the following request:

~~~
HTTP POST /apps/{appId}/clients/{clientId}/queues 

Input:

{
    protocolVersion: uint16,
    cipherSuite: uint16,
    appLabel: String
}

Output:

{
    keyQueueId: UUIDv4
}

~~~

If the above request is successful, a new key queue with unique identifier
`keyQueueId` and provided attributes is created. Note that the `clientId` and
`appId` are provided in the URI.

A gateway MUST NOT contain multiple key queues with the same combination of
protocolVersion, cipherSuite, and appLabel properties. 

## Key Queue Update

A gateway MUST support updating the key packages in an existing queue using the
following request:

~~~
HTTP PATCH /apps/{appId}/clients/{clientId}/queues/{keyQueueId}

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
`keyPackages` contains an MLS key package that is valid according to [MLS RFC].
If the above check fails, the request has no effect.

The request (if successful) results in the key queue `keyQueueId` (as in the URI)
being updated as follows:

1. If `isReset` is true, remove all key packages from the queue.
2. In any case, insert, all key packages from `keyPackages` to the queue.

The output of the request is the number of key packages in the queue after
update.

In addition, a gateway MAY support updating other key queue attributes. In this
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

If provided, `appLabel` replaces the respective attribute of the key queue.
If the gateway supports final keys and `finalKey` is provided, the gateway
SHOULD verify that `finalKey` contains an MLS key package that is valid
according to [MLS RFC]. The `finalKey` is stored for the given key queue,
replacing the previously stored final key (if present).

## Key Package Retrieval

A gateway MUST allow an application or gateway to retrieve a key package of a
given client using the following request:

~~~
HTTP GET /apps/{appId}/clients/{clientId}/keyPackage

Input:

{
    protocolVersion: uint16,
    cipherSuite: uint16,
    optional appLabel: String
    receiver_client_id: String
}

Output:

{
    keyPackage: Base64(TLS-serialized MLSMessage)
    optional isFinalKey: bool
}
~~~

The above request has the following effect:

// TODO: Should we really have isFinalKey or is that potentially a security
problem and we should say that the pool should just return an error in the event
there are no more keys.

* A key queue with attributes matching the provided `appId`,
  `clientId`, `protocolVersion`, `cipherSuite` and `appLabel` is chosen. If
  there is no such key queue, the request has no effect.
* If a non-final key in the queue is assigned to `receiver_client_id`, and that
  key package is not expired, then that key should be returned. The queue will
  not advance until the current key package is used for a meaningful group
  operation as described in [`GroupEvolution`].
* Else, if the above key queue contains (non-final) key packages, the first
  non-expired key package that has not been assigned a receiver client id
  should be assigned to the provided `receiver_client_id` and returned with the
  `isFinalKey` flag set to false. Key packages SHOULD be sorted by the
  `not-after` property of their `Lifetime` when choosing a key to return.
* Else, if there is a final key stored for the key queue, the output contains
  this final key and the `isFinalKey` flag is set to true.
* Else, the request has no effect.

### Advancing a Key Package Queue 

Key package retrieval is idempotent by design. Repeated requests with the same
queue properties and `receiver_client_id` combination MUST produce the same key
package until the queue is advanced. A queue is advanced by deleting the key
package assoiciated with a particular `receiver_client_id`, which will allow
that receiver to get a new key package the next time one is requested.
Advancing the key queue is dependent on the key package being used by a
meaningful group operation as described in [`GroupEvolution`].

Key queues MUST be automatically advanced beyond expired key packages regardless
of an individual key package's `receiver_client_id` property. A key package is 
determined to be expired if the `not-after` property of the key package's
`Lifetime` is beyond the current local server time. Applications MAY decide to
consider a key package expired earlier than its technical expiration. 

## Key Pool Deletion

TODO

# Managing Groups without Metadata Protection

In this section we assume that group membership is not required to be hidden
from gateways. For this case, each gateway implements functionality for
filtering, ordering and delivering MLS handshake messages.

At a high level, each gateway creates for each group a sequence of epochs. For
each epoch, it stores all information clients need to transition to this epoch.
For group current members, this includes MLS proposal and commit messages. For
clients invited by other members, this includes MLS welcome messages and ratchet
trees (one per epoch). The gateway keeps track of the tree itself, based on MLS
control messages received from applications or other gateways. Finally, if a
group enables joining via external commits, the gateway stores for external
joiners an MLS group info message for the current epoch.

Most important tasks of the gateway are: resolving conflicts in case multiple
commits are created at the same time (all clients must agree on one of them) and
validating received control messages (to the extent this is possible without
being a group member).

## Group Creation

// TODO: Make sure to mention that gateways MUST enforce that a key package is
only used once if it is marked as non-final in the group management section.


A gateway MUST support creation of a one-member group with the following
request:

~~~
HTTP PUT /apps/{appId}/groups 

Input:

{
    groupInfo: Base64(TLS-serialized MLSMessage),
    ratchetTree: Base64(TLS-serialized [optional<Node>])
}
~~~

The `groupInfo` and `ratchetTree` objects should be exported by the client who
created the group before sending any MLS messages. A gateway MUST validate the
above input using the following steps:

* The `groupInfo` contains a valid MLS GroupInfo object.
* `ratchetTree` is valid according to [MLS RFC] and is consistent with
  `groupInfo`.
* The epoch in `groupInfo` is `0` and the `ratchetTree` consists of a single
  node.
* The `group_id` in `groupInfo` is unique among all existing groups.

After the group is created, it can be refered to by the `group_id` from
`groupInfo`.

## Group Evolution

A group evolves when clients upload MLS proposal and commit packets. When a
gateway receives such a packet from an application, it MUST immediately forward
it to all gateways the application federates with.

### Proposals

~~~
HTTP PUT /apps/{appId}/groups/{groupId}/proposals

Input:

{
    packet: Base64(TLS-serialized MLSMessage)
}
~~~

### Commits

~~~
HTTP PUT /apps/{appId}/groups/{groupId}/epochs

Input:

{
    commitPacket: Base64(TLS-serialized MLSMessage),
    optional groupInfo: Base64(TLS-serialized MLSMessage),
    optional welcomePacket: Base64(TLS-serialized MLSMessage)
}
~~~

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
