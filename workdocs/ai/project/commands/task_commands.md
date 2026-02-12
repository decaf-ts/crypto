# Task Commands

These commands are related to managing individual tasks.

## `read task <ref>`
*   **Action:**
    1. Execute `read constitution` to get the configured `<TASK_KEY>`.
    2. Look for a `<TASK_KEY>_<ref>.md` file in `./workdocs/ai/project/specifications/tasks`.
    3. If not found, inform the user.
    4. If found, read it and wait for input.

## `update task <ref>`
*   **Action:**
    1. Execute `read task <ref>`.
    2. Update it with the provided input.

## `describe task <ref>`
*   **Action:**
    1. Execute `read task <ref>`.
    2. Describe the task.

## `plan task <ref>`
*   **Action:**
    1. Execute `read task <ref>`.
    2. Evaluate implementation strategy based on constitution, architecture, and existing abstractions.
    3. Identify Classes (Models, Repositories, Services, etc.) following `@decaf-ts` framework.
    4. Identify blockers and solutions.
    5. Update the `<TASK_KEY>_<ref>.md` file using the [Task Template](../specifications/task_template.md).

## `add task <task description>`
*   **Action:**
    1. Execute `read plan`.
    2. Find similar tasks.
    3. If new, generate a sequential ID.
    4. Execute `read constitution` to get the configured `<TASK_KEY>` and `<SPECIFICATION_KEY>`.
    5. Add a summary to the plan (or specification).
    6. Create `<TASK_KEY>_<ref>.md` in `./workdocs/ai/project/specifications/tasks` using the [Task Template](../specifications/task_template.md).
    7. Execute `plan task <ref>`.

## `clarify task <ref>`
*   **Action:**
    1. Execute `read task <ref>`.
    2. If input provided, treat as clarification and update task.
    3. If no input, identify blockers/clarifications and ask user.
    4. Update task file with responses.
    5. If unblocked, execute `update plan`.

## `execute task <ref>`
*   **Action:**
    1.  **Read Task:** Execute `read task <ref>`.
    2.  **Check Blockers:** Check for clarifications/blockers. If any, ask user.
    3.  **Git Branch (If Applicable):**
        *   Check `Git Workflow` in Constitution.
        *   If mode is `branch`: Execute `git branch <ref> <task_name>`.
    4.  **Implement:**
        *   Evaluate code changes required.
        *   Implement task and tests.
    5.  **Verify:** **Build, Test, Lint.** Only proceed if successful.
    6.  **Git Commit:**
        *   Execute `git commit <ref> <task_name>`.
    7.  **Git Merge (If Applicable):**
        *   If mode is `branch`: Execute `git merge <ref>`.
    8.  **Update Docs:**
        *   Update task file with results.
        *   Update plan with results.
    9.  **Next Step:** Execute `review plan`.
