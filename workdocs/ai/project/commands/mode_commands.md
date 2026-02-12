# Mode Commands

These commands control the operating mode of the agent.

## `auto mode`
*   **Action:**
    1. Proceed without questioning the user unless there are blockers or clarifications.
    2. Loop until all tasks are completed:
        a. Execute `review plan` to identify the next task.
        b. Execute `plan task <ref>`.
        c. If clarifications/blockers exist, **STOP** and ask the user.
        d. If clear, execute `execute task <ref>`.
        e. **Build, Test, Lint.**
        f. Restart loop.

## `god mode`
*   **Action:**
    1. Proceed without questioning the user.
    2. Loop until all tasks are completed:
        a. Execute `review plan` to identify the next task.
        b. Execute `plan task <ref>`.
        c. If clarifications/blockers exist:
            i. **DECIDE** on the best course of action based on the Constitution and project context.
            ii. **DOCUMENT** clearly that the decision was made by the agent and the rationale behind it in the task file.
            iii. Execute `clarify task <ref>` with the decision.
        d. Execute `execute task <ref>`.
        e. **Build, Test, Lint.**
        f. Restart loop.
