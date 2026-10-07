# 0001 Use a layered application structure

## Status
Accepted

## Context
CertHub must perform real TLS handshakes and certificate inspections, but the diagnostic logic should remain testable without reproducing every possible network failure. The tool will eventually integrate storage, monitoring, and external systems, and these capabilities must be added without coupling the core diagnostic rules to specific technologies. A clear separation between TLS concepts, use‑case orchestration, and infrastructure details ensures that future changes in networking, persistence, or hosting can often be accommodated without changing the core diagnostic logic.

## Decision
The application is structured into four layers with dependencies pointing inward:
- Domain layer, a class library containing TLS diagnostic concepts, rules, and evaluation logic. It is completely independent of networking, storage, and ASP.NET. Domain layer does not depend on any other layer.
- Application layer defines use cases and the probing interfaces required to perform TLS diagnostics. It orchestrates domain logic but does not implement technical details.
- Api layer is the entry point and composition root. It wires together the Application and Infrastructure layers
- Infrastructure layer implements the interfaces defined in the Application layer, including TLS probing, with persistence and notification implementations added in later milestones.
- The Lab project is standalone TLS playground used to simulate handshake scenarios, certificate issues, and failure modes. It is part of the solution, but has no project references to or from other projects.

## Consequences
- High testability: Domain and Application tests run without live network connections or infrastructure, enabling fast and deterministic unit tests.
- Clear separation of concerns: TLS implementation details, storage engines, and monitoring systems remain outside the core diagnostic logic.
- Extensibility: Alternative infrastructure implementations can be introduced behind Application interfaces, limiting changes to core logic. New capabilities may still require changes to application contracts and use cases.
- Realistic validation still required: Integration tests remain necessary to verify handshake behaviour, certificate chains, and real‑world TLS edge cases.
- Increased structural complexity: Multiple projects and boundaries introduce complexity in a small application, but they provide long‑term clarity and flexibility as the tool grows.
- Abstraction discipline: Interfaces will be introduced at external boundaries where they support separation and testing, rather than for every class.