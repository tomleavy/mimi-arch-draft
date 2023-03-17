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
 -  fullname: Joel Alwen
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

## Operational Context 

A basic federation scenario consists of a bi-directional data flow between
three types of actors: clients, application servers and MIMI gateways. Clients
communicate with application servers, application servers communicate with
gateway services, and gateway services communicate with other gateway services.

Typically, application servers are only responsible for transparently delivering
messages 

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

An example message flow for Alice creating a group with Carol is as follows:

1. Carol registers a key package in MIMI Gateway B. The key package is delivered
   via Application Server 3.
2. Alice asks MIMI Gateway A, via Application Server 1, for a key package for
   Carol on Domain B.
3. MIMI Gateway A finds MIMI Gateway B via Domain B and requests a key package
   for Carol.
4. MIMI Gateway B sends back the key package Carol registered in Step 1. MIMI
   Gateway A sends the key package to Alice, via Application Server 1.
5. Alice creates a new MLS session and  sends a welcome message for Carol to
   MIMI Gateway A.
6. MIMI Gateway A sends the welcome message to MIMI Gateway B .
7. When Carol comes online, MIMI Gateway B sends her the welcome message via
   Application Server 3. Carol joins the session.


## Gateway Overview

The MIMI Gateway is designed to be a hybrid of AS and DS functionality as
defined by `MLS Architecture`. It has an internal interface for
applications within its domain(s) to federate with each other, as well as an
external interface that allows for cross-domain federation. If an application
supports federation then it MUST [support domains](#identity-providers) and it 
MUST be aware of which domain(s) its clients belong to. This will be needed, 
for example, to perform basic sanity checks when clients register new
key packages. 

A gateway acts as a permissioned database of the following information:

* Unique identifiers of clients that can be queried by application-defined tags.
* Queryable queues of MLS Key Packages indexed by identifier, protocol version,
cipher suite and a custom label.
* MLS proposals, commits, welcome messages and ratchet trees indexed by MLS
`group_id` and `epoch_id`.

# Identity Providers

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

Each identity provider is configured using an `IdentityConfiguration` object
which helps synchronize various provider specific options across applications.
The configuration has a unique type value that identifies the provider type and
two flags `supports_accounts` and `supports_domains` indicating whether the
provider supports the notions of accounts and domains respectively.
Conceptually, an account is a collection of clients (usually belonging to one 
user) and a domain is a collection of accounts (e.g. belonging to a particular 
organization). Besides this generic configuration a provider can also have
additional custom opaque parameters.

~~~
IdentityConfiguration
{
    "identity_provider_type": number,   //uint8
    "supports_accounts": boolean,
    "supports_domains": boolean,
    "parameters": object 
}
~~~

An example interface of an identity provider is as follows:

~~~
Identity
{
    "public_key": SignaturePublicKey,
    "credential": Credential
}

ApplicationContext
{
    "context": object
}

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

If the provider is configured to support accounts the interface could, for
example, include the following additional function.

~~~
    fn client_account(Identity identity) -> String
~~~

Similarly, when configured to support domains the interface could be extended
with the following function.

~~~
    fn client_domain(Identity identity) -> String
~~~

The rest of this section describes two examples of identity providers.

## Basic Identity Provider 

The basic identity provider is the minimal implementation of an identity
provider. It does not support accounts nor domains and has the following
properties:

* Basic is the only type of credential that is supported.
* Credentials are always valid.
* Leaf and entity identifiers are equal to the bare assertion of identity
  provided by a BasicCredential.

## X.509 Identity Provider

The X.509 Identify Provider allows for hierarchical identities based on
certificate chains. The provider is configured via the generic
`IdentityConfiguration` object and the X.509 Identity Provider specific
`X509Parameters` object contained within. Besides clients, depending on how the
corresponding flags in `IdentityConfiguration` are set, the X.509 Identity
Provider may also support accounts and/or domains.

The only credential type supported by the X509 Identity Provider is `x509` .
An X.509 credential contains a chain of 1 or more X.509 certificates, encoded as
specified in {{!I-D.ietf-mls-protocol}}. Certificate chains MUST be validated
according to the rules in {{!RFC5280}} using the trust roots agreed upon by the
(TODO: Some sort of extension dealing with trust root negotiation).

~~~
X509ApplicationContext
{
    "msg_timestamp": number //uint64
}

X509DeviceHandleRange
{
    "start": uint8,
    "end": uint8
}

X509Parameters
{
    // required
    "device_handle_range":
    {
        "start": number,  //uint8 
        "end"; number     //uint8
    },

     // required when IdentityConfiguration.support_accounts == true
    "account_handle_offset": number, //uint8

     // required when IdentityConfiguration.support_domains == true    
    "domain_name_offset": number, //uint8
}
~~~

A given `IdentityConfiguration` parameter set with custom X.509 Identity
Provider settings `"parameters": X509Parameters` are valid if the
following conditions are all met. The device handle range MUST not end before it
starts.

~~~
Assert (parameters.device_handle_range.end >= 
        parameters.device_handle_range.start)
~~~

If the X509 Identity Provider is configured to use accounts then the account
handel offset MUST strictly succeed the device handle range in the
certificate chain counting from the leaf certificate up. 

~~~
If (IdentityConfiguration.supports_accounts == true) {
    Assert (parameters.account_handle_offset >
            parameters.device_handle_range.end)
}
~~~~

Many messaging systems use multi-client (e.g. multi-device) accounts.
Accounts are also referred to as users {{?I-D.draft-mahy-mimi-identity}}. 
Account handles are calculated like client handles but based on the certificate
at the Account Handle offset (instead of Client Handle range).

If the provider is configured to use domains then the domain name offset MUST
strictly succeeds the device handle range in the certificate chain counting
from the leaf certificate up.

~~~
If (IdentityConfiguration.supports_domains == true) {
    Assert (parameters.domain_name_offset > parameters.device_handle_range.end)
}
~~~

Finally, if both domains and accounts are used then the domain name offset MUST
also strictly succeed the account handle offset.

~~~
If (IdentityConfiguration.supports_domains == true) &&
   (IdentityConfiguration.supports_accounts == true) {
    Assert (parameters.domain_name_offset > parameters.account_handle_offset)
}
~~~~

### X.509 Identifiers

Each client has a handle (i.e. a human readable name). If the X509 Identity
Provider is configured to not use domains then client handles MUST be unique
across all clients registered in the application. However, if domains are being
used then client handles MUST only be unique within scope of the client's
domain.

If the Provider is configured to use accounts then a client handle is defined
to be the concatenation of its account handle followed by its device handle
seperated by a "/". When accounts are not used the client handle is simply its
device handle.

~~~
If (IdentityConfiguration.supports_accounts == true) {
    client_handle := account_handle + "/" + device_handle;
} Else {
    client_handle := device_handle;
}
~~~

End piont handles, account handles (when used) and domain names (when used) are
derived from subject Common Name fields in a client's credential certificate
chain as described bellow. To ensure unambiguous URI's for clients and accounts
(as described in {{?I-D.draft-mahy-mimi-identity}}) the Common Name fields found
used to derive the handles MUST NOT contain any of the 5 special characters
"@", "/", "#", "$" and ":". 

### X.509 Device Handles
A client's device handle is derived by concatenating the X.509 subject Common
Name fields of a range of certificates in client's certificate chain credential.
The range to use is defined by the `start` and `end` offsets in the 
`device_handle_range` field of the `X509Parameters` object. Offsets begin at
the leaf certificate wich has offset 0 and count upwards towards the root
certificate in the chain. Each Common Name field in the range is seperated from
the next in the client handle using a ":" character as delimiter.

### X.509 Account Handles

When the X509 Identity Provider is configured to use accounts a client's account
handle is calculated just like its device handle but using only the
certificate with the offset given by the `account_handle_offset` field in the
`X509Parameters` object.

### X.509 Domains Names

When the X509 Identity Provider is configured to use domains a client's domain
name is calculated just like its device handle but using only the certificate
with the offset given in the `domain_name_offset` field in the `X509Parameters`
object.

### Handing Timestamps 

// TODO: Utilize X509ApplicationContext in order to set a msg_timestamp that
will be used to determine if the certificate chain was valid at a specific time
of use. 

// TODO: Describe how to check for expired certificates at commit time and
propose their removal. Other clients / Server MUST verify this has been done
based on the timestamp of the message assigned by the server and reject
accordingly.

# Applications

A gateway can manage information for multiple applications that may or may not
federate with each other. An application is identified by an 
ApplicationID and its behavior is defined by an ApplicationConfiguration.
ApplicationID is defined as a UUIDv4 string and MUST be unique across all
gateways that are federated with one another. // TODO: Link to UUIDv4 definition

~~~
ApplicationConfiguration
{
    "identity_configuration": IdentityConfiguration,
    "id": UUIDv4
    // TODO: Could apps use multiple IdentityConfigurations?
    // TODO: Is additional configuration needed?
}
~~~

In order for interoperable federation to exist between domains, the
ApplicationConfiguration for a particular ApplicationId MUST match between
each domain that is participating. Application configurations hosted on a
particular gateway MAY be public by providing access to the following API route:

~~~
HTTP GET /apps 

Output:

[ApplicationConfiguration]
~~~

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
searching by the above tag 1. allows listing all clients owned by
`alice@org`, which is a typical scenario in messaging applications where
Bob invites a multi-device account of Alice to join a chat. Searching by the tag 
2. above allows to add an arbitrary moderator, or all clients owned by
entities with the right clearance.

## Identity Registration

When a client registers with an application, the application registers
the client with the identity service using the following request:

~~~
HTTP POST /apps/{appId}/clients 

Input:

{
    clientHandle: IdentityProvider.client_handle,
    tags: [String]
}

Output:

{
    clientId: UUIDv4
}

~~~

In the above figure, the returned `clientId` is the new identifier assigned to
the client by the identity service. Services MUST ensure that `clientId` and
`clientHandle` are both unique among all registered clients. 

A client MAY be editable by the following request:

~~~
HTTP PATCH /apps/{appId}/clients/{clientId}

Input:

{
   clientHandle: IdentityProvider.client_handle,
   tagsToAdd: [String],
   tagsToRemove: [String]
}
~~~

Patching an existing client MUST fail if changing `clientHandle` results in a
conflict with another existing client.

## Client Discovery

An application can list identifiers of all clients with a given tag using the
following request:

~~~
HTTP GET /apps/{appId}/clients 

Input:

{
    optional domain: String,
    tag: String
}

Output:

{
    identities: [
        {
            clientId: UUIDv4,
            clientHandle: IdentityProvider.client_handle,
            tags: [String]
        },
    ...
    ]
}

~~~

For applications that use federation, the `domain` value MUST be provided. A
gateway processes the request as follows. If `domain` is provided and it is not
assigned to the processing gateway, then the gateway transparently passes the
input to a gateway to which `domain` is assigned, waits for the output and
passes it to the calling entity. Otherwise, it returns the registered identity
data for all clients that have `tag` associated with them: their `clientId`,
`clientHandle` and all tags.

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

Upon the above request, the key queue `keyQueueId` (as in the URI) is updated
as follows:

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
according to {{!I-D.ietf-mls-protocol}}. The `finalKey` is stored for the given
key queue, replacing the previously stored final key (if present).

## Key Package Retrieval

A gateway MUST allow an application or gateway to retrieve a key package of a
given client using the following request:

~~~
HTTP GET /apps/{appId}/clients/{clientId}/keyPackage

Input:

{
    optional domain: String,
    protocolVersion: uint16,
    cipherSuite: uint16,
    optional appLabel: String
    receiver_client_id: String,
}

Output:

{
    keyPackage: Base64(TLS-serialized MLSMessage)
    optional isFinalKey: bool
}
~~~

For applications that use federation, the `domain` value MUST be provided. A
gateway processes the request as follows. If `domain` is provided and it is
different than the processing gateway's domain, then the gateway transparently
passes the input to a gateway from `domain`, waits for the output and passes it
to the calling entity. Otherwise, it processes the request using the following
steps:

* A key queue with attributes matching the provided `appId`,
  `clientId`, `protocolVersion`, `cipherSuite` and `appLabel` is chosen. If
  there is no such key queue, the request has no effect.
* If a non-final key in the queue is assigned to `receiver_client_id`, and that
  key package is not expired, then that key should be returned. The queue will
  not advance until the current key package is used for a meaningful group
  operation as described in {{group-evolution}}.
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
package associated with a particular `receiver_client_id`, which will allow
that receiver to get a new key package the next time one is requested.
Advancing the key queue is dependent on the key package being used by a
meaningful group operation as described in {{group-evolution}}.

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

## Group State

A gateway stores the following data for each group that has been created:

* `group_id`: The group id generated by MLS that uniquely identifies the
  group.
* `epochs`: A sequence of data structures describing MLS epochs. Each epoch
  contains the following information: the MLS `epoch_id` (a counter), the MLS
  commit packet that created the epoch and the MLS proposal packets included in
  the above commit by reference.
* `clients`: A list of current and possibly past group members. For each
  member invited by a welcome message, the gateway stores information they need
  to join the group: the welcome packet and, if necessary, the ratchet tree.
  Clients are identified by values returned by the `client_handle` function of
  the group's Identity Provider.
* Information related to the current epoch, i.e., the entry in `epochs` with the
  highest `epoch_id`:
  * `currentProposals`: The list of MLS proposal packets uploaded in the
    current epoch.
  * `currentTree`: The current ratchet tree
  * `currentContext`: The current MLS GroupContext.
  * `currentGroupInfo`: The MLS group info message needed by clients joining
    via external commits, if provided by current group members.

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
* `ratchetTree` is valid according to {{!I-D.ietf-mls-protocol}} and is
  consistent with `groupInfo`.
* The epoch in `groupInfo` is `0` and the `ratchetTree` consists of a single
  node.
* The `group_id` in `groupInfo` does not identify an existing group.

As a result of the above request, a gateway creates a new group identified by
`group_id` from `groupInfo`, with a single epoch in `epochs` and a single member
from the single leaf in `ratchetTree`.

## Group Evolution

A group evolves when clients upload MLS proposal and commit packets. When a
gateway receives such a packet from an application, it MUST immediately forward
it to all gateways the application federates with.

// TODO: decide if we want to implement this Matrix-style (above) or by having
// one gateway being the leader, or both.

### Proposals

A gateway MUST support uploading proposals created in the current epoch using
the following request:

~~~
HTTP PUT /apps/{appId}/groups/{groupId}/proposals

Input:

{
    packet: Base64(TLS-serialized MLSMessage)
}
~~~

A gateway processes the above request using the following steps:

* Verify that a group with `group_id` inside `packet` has been created.
* Verify that `packet` is a valid proposal in the context of the current epoch
  of the group identified by `group_id`, according to
  {{!I-D.ietf-mls-protocol}}.
* Add `packet` to the `currentProposals` of the group identified by `group_id`.

A gateway MUST support downloading current proposals (meant for a client who
is about to perform a commit) using the following request:

~~~
HTTP GET /apps/{appId}/groups/{groupId}/proposals

Output:

{
    messages: [ Base64(TLS-serialized MLSMessage) ]
}
~~~

The response includes all packets from `currentProposals` of the group
identified by `groupId`.


### Commits

A gateway MUST support uploading commits using the following request:

~~~
HTTP PUT /apps/{appId}/groups/{groupId}/epochs

Input:

{
    commitPacket: Base64(TLS-serialized MLSMessage),
    optional groupInfo: Base64(TLS-serialized MLSMessage),
    optional welcomePacket: Base64(TLS-serialized MLSMessage)
}
~~~

A gateway processes the above request using the following steps:

* Verify that a group with `group_id` inside packet has been created.
* Verify that `commitPacket` is a valid commit in the context of the current
  epoch of the group identified by `group_id`, according to
  {{!I-D.ietf-mls-protocol}}. That is, the gateway performs all checks a group
  member does, except those that require group secrets: verifying the membership
  and confirmation tags.
* Update the state of the group identified by `group_id` as follows:
  * Add a new epoch to `epochs` with the commit packet set to `commitPacket`.
    The new epoch's proposal packets are copied from the group's
    `currentProposals`, identified by the proposal references in `commitPacket`.
  * Update the group's `currentTree` and `currentContext` based on
    `commitPacket` and `currentProposals`, as described in
    {{!I-D.ietf-mls-protocol}}. Then, set `currentProposals` to empty and
    `currentGroupInfo` to `groupInfo` from the input (or empty if not given). 
  * If the commit includes add proposals, verify that `welcomePacket` is
    provided. Register it and the new `currentTree` as the joining information
    for each new member, identified by the value returned by the `client_handle`
    function of the group's Identity Provider.
* If the commit includes add proposals, advance the key queue of each added
  member.
  // TODO: be more precise

A gateway MUST support downloading control messages (meant for clients who
transition to epochs created by other members) using the following request:

~~~
HTTP GET /apps/{appId}/groups/{groupId}/control-msgs

Input:

{
    startEpochId: uint64,
    optional endEpochId: uint64
}

Output:

{
    messages: [ Base64(TLS-serialized MLSMessage) ]
}
~~~

The response to the above request includes all MLS packets needed to transition
from `startEpochId` to `endEpochId` or, if not provided, to the current epoch.
More precisely, the response includes all commits and proposals committed by
reference from those entries in `epochs` of the group identified by `groupId`
with `epoch_id` between `startEpochId` and `endEpochId` (inclusive).

## Joining

Clients can join an MLS session in two ways: using a welcome message if they are
invited by others or otherwise using a group info message. A gateway MUST
support joining by welcome messages using the following request:

~~~
HTTP GET /apps/{appId}/clients/{clientHandle}/welcome-msgs

Output:

{
    joinInfos: [
        {
            welcome: Base64(TLS-serialized MLSMessage),
            optional ratchetTree: Base64(TLS-serialized optional Node<V>)
        },
        ...
    ]
}
~~~

// TODO: add some sort of transaction mechanisms s.t. clients don't download
// the same thing many times

The above output contains joining information for all groups into which the
client identified by `clientHandle` has been invited. This includes the welcome
packet uploaded by the committer inviting it and the ratchet tree in case the
group does not use the ratchet tree extension.

Further, a gateway MUST support joining using group info using the following
request:

~~~
HTTP GET /apps/{appId}/groups/{groupId}/group-info

Output:

{
    groupInfos: [
        {
            groupInfo: Base64(TLS-serialized MLSMessage),
            optional ratchetTree: Base64(TLS-serialized optional Node<V>)
        },
        ...
    ]
}
~~~

// TODO: should the gateway implement some sort of group searching by handles,
// or is it left to applications?


# Key Package Validation

A gateway receives key packages from applications and other gateways in
following situations:

* During Key Queue Update and Key Package Retrieval
* When processing MLS packets containing key packages (add proposals, commits,
  etc.)

Whenever a gateway receives a key package, it MUST verify that the key package
is valid according to {{!I-D.ietf-mls-protocol}} (for processing MLS packets,
this is likely done automatically when the gateway validates the packet using
MLS). Key packages in key queues are encoded as MLSMessage.

For applications using domains, a gateway MUST also validate the domain of each
received key package as follows:

* The gateway uses the application's IdentityProvider to retrieve the `domain`
  from the MLS Credential in the key package. For example, this can be done
  using the provider's `identity` and `client_domain` functions.
* If the gateway received the key package from an application (e.g. in an add
  proposal), a gateway verifies that `domain` is assigned to itself. Else, if
  the gateway received the key package from another gateway, then it verifies
  that `domain` is assigned to that other gateway.

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
