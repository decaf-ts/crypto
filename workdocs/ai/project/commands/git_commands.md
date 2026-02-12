# Git Commands

These commands manage the Git workflow and configuration.

## `git mode <mode>`
*   **Action:**
    1.  **Read Constitution:** Read the [Constitution](../constitution.md) to check the current configuration.
    2.  **Update Mode:** Update the `Mode` setting in the "Git Workflow" section of the Constitution to the specified `<mode>` (`commit` or `branch`).
    3.  **Confirm:** Confirm the change to the user.

## `git config keys <type> <key>`
*   **Action:**
    1.  **Read Constitution:** Read the [Constitution](../constitution.md).
    2.  **Update Key:** Update the specified key type (`Task` or `Specification`) in the "Git Workflow" section to the new `<key>`.
    3.  **Confirm:** Confirm the change to the user.

## `git commit <ref> <description>`
*   **Action:**
    1.  **Check Mode:** Check the "Git Workflow" mode in the Constitution.
    2.  **Commit:**
        *   If mode is `commit` or `branch`: Commit all staged changes with the message: `<KEY>-<ref> - <description>`.
        *   Use the configured `<KEY>` for the reference type (e.g., `TASK` or `SPECIFICATION`).

## `git branch <ref> <description>`
*   **Action:**
    1.  **Check Mode:** Check the "Git Workflow" mode in the Constitution.
    2.  **Branch:**
        *   If mode is `branch`: Create and checkout a new branch named `<KEY>-<ref>-<description>`.
        *   Use the configured `<KEY>` for the reference type.
    3.  **Error:** If mode is `commit`, inform the user that branching is disabled in this mode.

## `git merge <ref>`
*   **Action:**
    1.  **Check Mode:** Check the "Git Workflow" mode in the Constitution.
    2.  **Merge:**
        *   If mode is `branch`:
            *   Checkout the `Main Branch` (configured in Constitution).
            *   Merge the feature branch `<KEY>-<ref>-...` into the main branch.
            *   (Optional) Delete the feature branch.
    3.  **Error:** If mode is `commit`, inform the user that this command is not applicable.
