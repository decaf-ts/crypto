# CONSTITUTION

This document outlines the structure, conventions, and architecture of the project to ensure a Large Language Model (LLM) can effectively assist in its development.

## 0. Development Workflow - NON NEGOTIABLE

After every code change, you **must** run the following commands to ensure code quality and prevent regressions:

1.  **Lint:** `npm run lint`
2.  **Build:** `npm run build`
3.  **Test:** `npm run test` (Use targeted tests for specific changes).

(These must be run in the appropriate root)

## 1. Core Philosophy

The project create a cross environment (node/browser) wrappers around standard cryptographic functions:

- `./src/bin`: cli entry point;
- `./src/browser`: browser entry point;
- `./src/node`: node entry point;
- `./src/common`: shared functionality between browser and node;
- `./src/jwt`: simple jwt related functionality;
- `./src/integration`: integration with the decaf-ts framework;
- `./src/psk`: conversion of old deprecated crypto library;

### References:
- `./psk-crypto`: old repository, meant to be ported to typescript using up to date crypto libraries;
- `./psk-crypto/jose`: meant to be replaced in full with the 'jose' library and eventual wrappers to maintaind apis;
- `./psk-crypto/js-mutual-auth-ecies`: meant to be replaced in full with the 'eciesjs' library and eventual wrappers to maintaind apis;
- `./psk-crypto/jsonWebToken`: meant to be replaced in full with the 'jsonwebtoken' library and eventual wrappers to maintaind apis;
- `./psk-crypto/lib/asn1`: meant to be replaced in full with the 'asn1' library and eventual wrappers to maintaind apis;
- `./tests`: bad tests in a dead framework - to be ported to jest tests;

### 1.1. CORE DESIGN INVARIANTS

These rules are **non-negotiable**.

1.  All code ported from psk-crypto must be in `./src/psk`;
2. no callbacks in code. always user async/await whenever possible. otherwise offer a justification why it was not suitable

## 3. Testing Philosophy
*   **Unit Tests:** All functionality MUST have corresponding unit tests.
*   **Integration Tests:** Scenarios involving external dependencies MUST be covered.
*   **Test Coverage:** New features or bug fixes must be accompanied by tests.

## 4. Git Workflow

This section defines the Git workflow for the agent.

*   **Mode:** `commit`
    *   **Description:** Defines the git strategy.
    *   **Options:**
        *   `commit`: All changes are committed directly to the main branch after a task is successfully completed.
        *   `branch`: Create a new branch for each task, and create a Pull Request when the task is complete.
*   **Main Branch:** `master`
    *   **Description:** The primary branch for commits and for opening pull requests against.
*   **Commit Keys:**
    *   **Task:** `TASK`
    *   **Specification:** `SPECIFICATION`

## 5. How to Fulfill a Request: A Checklist

1.  **Identify Goal & Service:** Determine the responsible service/class.
2.  **Create/Modify Object:** Ensure it's properly decorated (if applicable).
3.  **Implement Method:** Use descriptive names and pass `context`.
4.  **Write Tests:** Unit and Integration tests are mandatory.
5.  **Follow Git Workflow:** Adhere to the configured git `Mode` for branching and committing.
