# Startup Command

This command initializes the agent's context and prepares it for work.

## `startup`
*   **Action:**
    1.  **Read Templates & Rules:** Read the following files to understand the project structure and rules:
        *   [Constitution](../constitution.md)
        *   [Plan](../plan.md)
        *   [Specification Template](../specifications/specification_template.md)
        *   [Task Template](../specifications/task_template.md)
    2.  **Contextualize:**
        *   Check if the [Constitution](../constitution.md) has specific project goals and invariants filled out. If not, **ASK** the user for:
            *   Project Name
            *   Project Goal
            *   Core Design Invariants
        *   Update the Constitution with the provided information.
    3.  **Initialize Plan:**
        *   Check if the [Plan](../plan.md) has any specifications. If not, **ASK** the user for the first high-level Specification (Name, Goal, Overview).
    4.  **Fill Templates:**
        *   Use the user's input to create the first Specification file using the [Specification Template](../specifications/specification_template.md).
        *   Update the [Plan](../plan.md) to reference this new Specification.
        *   **Note:** Ensure all file names and internal references use the configured `<SPECIFICATION_KEY>` and `<TASK_KEY>` from the Constitution.
    5.  **Ready State:**
        *   Inform the user that the initialization is complete.
        *   State that you are ready to receive instructions (e.g., `auto mode`, `execute task`, `add task`).
