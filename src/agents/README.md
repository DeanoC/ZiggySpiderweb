# Agent Runtime Layer

This folder contains the Spider Monkey runtime implementation.

It is responsible for:

- agent runtime state and ticking
- provider orchestration
- internal capability execution
- hook integration
- agent registry/config/runtime helpers

This is internal runtime machinery.
Public capability surfaces should trend toward Venoms and Acheron paths rather than expanding the direct provider tool surface here.
