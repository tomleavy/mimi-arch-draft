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

## Scope:
* interface between AS and MLS -- something AS has to implement for both
  client and back-end
* interface between AS and application, split into 3 components
* Overview of services and very high-level of how they are used together.
* ?? how components federate

## Actors
* back-end
* application
* client

// make clear that client never talks to backend and that app should
// implement access control itself

# AS - MLS Interface

Define the interface.

# Identity Service

The identity service implements client discovery. It assigns to each
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

## Registering Clients
When a client registers with an application, the application registers
the client with the identity service using the following interface.

~~~
create_identity(
    application_id: UUID,
    client_identity: Blob, // The client's credential, e.g. and X509 certificate
    tags: Tags // A list of tags used to search for identities of another entity
) -> client_id: UUID 
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

Give (the default) example: Default Identity System : Hiearchical X.509 cert chains.

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

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

---
