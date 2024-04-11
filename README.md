# Timeline

*This should contain the timeline, which can be defined as a Gantt chart using [mermaid](https://mermaid-js.github.io/mermaid/).*

```mermaid
gantt
dateFormat  YYYY-MM-DD
title Project Timeline
todayMarker off


section Overview

   Project Window: over1, 2024-03-01, 2024-08-31
   Planned: over2, 2024-03-01, 2024-08-10
   Stretch: over3, after over2, 2024-08-31

section Background

    Read theory in SCION book: rev1, 2024-03-01, 4w
    Familiarize with existing code: rev2, 2024-03-01, 6w
    Familiarize with CYD test network: rev3, after des0, 3w

section Design
    Setup remote access to network infrastructure: des0, 2024-03-08, 1w
    Define attacker model: des1, 2024-03-15, 1w

section Analysis

    Gray-Box Analysis: anal1, after des1, 8w
    Black-Box Analysis: anal2, after anal1, 6w

section Evaluation
    Evaluation Results: eval1, after anal2, 3w
    Improvements: eval2, after eval1, 2w


section Documentation

    Create/Setup Project (Latex): doc0, 2024-03-01, 1d
    Background: doc1, 2024-03-08, 4w
    Attacker model: doc2, after des1, 1w
    Analysis: doc3, after doc2, 14w
    Evaluation: doc4, after doc3, 3w


    Intro/Motivation/Discussion/Conclusion: doc5, after doc4,2w
    Clean up: doc6, after doc5, 2024-08-31



```

# Usage
1. Clone the repository
```bash
git clone --recurse-submodules <repository-url>
```

# Template for a student project repository

This repository serves as the template for every student project at the CYD campus.

Important notes:

* *Naming convention:* The name of the project repository should follow this format:
`[year]_[student first name]-[student last name]_[project name]` (e.g., `2023_Max-Muster_Making-everything-secure`)

* *Structure:* The repository comes with a predefined directory structure. This should be used in general, but it can be extended with additional folders as needed.

* *No classified information:* It is not allowed to use GitHub to store classified contents. Classified projects must not use GitHub.

* *During the project:* It is up to the student(s) and advisor(s) to define how GitHub should be used during the project (e.g., it is possible to use Overleaf for the report). However, at the end of the project, all contents need to be on GitHub (see below).

* *At the end of the project:* Make sure that the following data is in the repository:
    - Latest version of source code and documentation (if available)
    - Final report (in PDF and raw format (e.g., LaTeX or Word))
    - Final presentation (in PDF and raw format (e.g., LaTeX or PowerPoint))

* *Repository remains private:* This repository remains private (i.e., only accessible for specific users). If code should be made open source, this needs to happen in a separate repository. The student loses access to the repository after the project ends.
