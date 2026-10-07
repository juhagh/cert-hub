# CertHub Architecture Overview

## Problem

TLS connectivity failures can be difficult to diagnose when certificate configuration, trust relationships and runtime behaviour are not readily visible.

Common diagnostic challenges include:

- Identifying which certificates and trust stores a service actually uses.
- Understanding certificate chains and the trust requirements of each connection.
- Distinguishing certificate validation failures from other connection failures when logs provide limited detail.
- Tracking certificate expiry and verifying that renewed certificates have been loaded by the intended service.

CertHub aims to make these conditions easier to investigate by reporting diagnostic findings alongside the evidence available from a connection attempt.

## First Milestone

The caller supplies an HTTPS URL. CertHub attempts a TLS connection to its host and port, using the hostname for server identity validation.

The diagnostic check:

- Reports available certificate metadata, validation findings and connection errors.
- Inspects the TLS connection without sending an HTTP request to the target.
- Treats a failed handshake as an expected diagnostic outcome and preserves any available evidence.
- Uses a bounded timeout and supports cancellation.
- Operates against controlled lab services.

Certificate validation remains enabled. The report distinguishes observed failures from possible causes that require further investigation.

## Scope

The first milestone covers on-demand server TLS diagnostics against controlled lab endpoints.

Client certificates, persistent storage, scheduled checks, notifications and public deployment are outside this milestone.

## Future Work

Planned extensions include:

- Client certificate support for mutual TLS diagnostics.
- Persistent diagnostic history.
- Scheduled monitoring and certificate expiry alerts.
- Azure deployment with operational logging and automated delivery.

## Application Structure

The application uses a layered structure with dependencies directed towards the domain and application layers.

- **Domain:** Diagnostic concepts and rules, independent of networking, storage and ASP.NET.
- **Application:** Coordinates use cases and defines interfaces for external capabilities.
- **Infrastructure:** Implements TLS connections and, in later milestones, persistence and notifications.
- **Api:** Defines HTTP contracts, validates requests, maps responses and composes application dependencies.

The TLS lab is independent of the product projects. Product and lab services interact over network connections rather than project references.

## TLS Lab

The lab provides controlled, reproducible scenarios for investigating TLS behaviour.

It begins with a successful server TLS connection, then introduces individual failure conditions such as an untrusted certificate authority, a hostname mismatch or an expired certificate.

Each scenario documents its configuration, expected outcome, observed evidence and resolution. This supports both learning and repeatable verification of CertHub’s diagnostic behaviour.