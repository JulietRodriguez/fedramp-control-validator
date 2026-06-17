# Architecture

`fedramp-control-validator` is a small, dependency-light pipeline. Evidence
flows left to right: AWS Config compliance findings are parsed into a typed
model, scored against the FedRAMP Moderate control catalog, then rendered for
humans (CLI / dashboard) and machines (OSCAL).

```mermaid
flowchart LR
    subgraph Input
        A1[AWS Config findings JSON<br/>simplified or native shape]
    end

    A1 --> P[parsers.py<br/>FindingSet]

    subgraph Knowledge
        K[catalog.py<br/>control families + titles<br/>Config rule -> control map]
    end

    P --> V[validator.py<br/>score each control:<br/>pass / fail / partial / n-a]
    K --> V

    V --> R[ValidationReport<br/>FamilyScore[] + ControlResult[]]

    R --> G[gap.py<br/>gap analysis]
    R --> O[oscal.py<br/>OSCAL 1.1.2<br/>Assessment Results]

    G --> CLI[cli.py<br/>Rich terminal report]
    R --> CLI
    G --> DASH[dashboard.py<br/>Streamlit dark UI]
    R --> DASH
    O --> CLI
    O --> DASH
```

## Module responsibilities

| Module | Responsibility |
| ------ | -------------- |
| `models.py` | Dataclasses + status vocabulary (`Finding`, `FindingSet`, `ControlResult`, `FamilyScore`, `ValidationReport`). |
| `parsers.py` | Load AWS Config findings JSON (simplified, native `EvaluationResults`, or bare list). |
| `catalog.py` | FedRAMP Moderate control catalog, NIST family titles, and the AWS Config rule → control mapping. |
| `validator.py` | The scoring engine. Classifies each control and rolls families up. |
| `gap.py` | Derives the gap analysis (failing/partial controls + reasons). |
| `oscal.py` | Serialises a report to OSCAL 1.1.2 Assessment Results. |
| `cli.py` | Rich-powered terminal interface and CI score gate. |
| `dashboard.py` | Streamlit dashboard with the dark security-tool theme. |

## Scoring model

A control maps to one or more AWS Config rules. For each control the engine
collects every *evaluated* finding (`COMPLIANT` / `NON_COMPLIANT`; other values
are ignored) for those rules:

| Evaluated resources | Control status |
| ------------------- | -------------- |
| none | `not-assessed` |
| all compliant | `pass` |
| all non-compliant | `fail` |
| a mix | `partial` |

A family rolls up its assessed controls the same way (all pass → `pass`, all
fail → `fail`, otherwise `partial`). The family/overall **score** is a weighted
percentage where each `pass` counts as 1.0 and each `partial` as 0.5.
