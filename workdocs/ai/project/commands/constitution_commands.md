# Constitution Commands

These commands are related to reading and updating the project's constitution.

## `read constitution`
*   **Action:** Read the `./workdocs/ai/project/constitution.md` file.
*   **Next Step:** Wait for more input.

## `update constitution | add to constitution`
*   **Action:** 
    1. Execute `read constitution`.
    2. Add the requested information to the constitution consciously.
    3. **Constraint:** Never delete existing information unless explicitly requested.
    4. **Goal:** Keep information organized and readable for an LLM to properly interpret the rules.
