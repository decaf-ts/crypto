# Plan Commands

These commands are related to managing the project plan.

## `read plan`
*   **Action:**
    1. Execute `read constitution`.
    2. Read the `./workdocs/ai/project/plan.md` file.
*   **Next Step:** Wait for more input.

## `update plan`
*   **Action:** Update the `./workdocs/ai/project/plan.md` file with the provided input.

## `review plan`
*   **Action:**
    1. Execute `read plan`.
    2. Propose next tasks according to priority and state of conclusion.
    3. **Constraint:** Always pick the highest priority tasks unless additional conditions are provided by the user.
