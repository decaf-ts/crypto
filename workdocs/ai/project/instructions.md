This is a multi repo project

# Project Decaf-mcp Instructions

This document outlines the structure, conventions, and architecture of the "the decaf-mcp" project to ensure a Large Language Model (LLM) can effectively assist in its development.

## Commands

When asked to execute a command, **ignore all other instructions you were not asked to do**. Do not add unnecessary pollution to the context when it's not needed.

Refer to the specific command files for detailed instructions:

*   **Startup:** [Startup Command](./commands/startup_command.md) (`startup`)
*   **Git:** [Git Commands](./commands/git_commands.md) (`git mode`, `git config keys`, `git commit`, `git branch`, `git merge`)
*   **Constitution:** [Constitution Commands](./commands/constitution_commands.md) (`read constitution`, `update constitution`)
*   **Plan:** [Plan Commands](./commands/plan_commands.md) (`read plan`, `update plan`, `review plan`)
*   **Specifications:** [Specification Commands](./commands/specification_commands.md) (`read specification`, `update specification`, `add specification`)
*   **Tasks:** [Task Commands](./commands/task_commands.md) (`read task`, `update task`, `plan task`, `execute task`, etc.)
*   **Modes:** [Mode Commands](./commands/mode_commands.md) (`auto mode`, `god mode`)

**NOT NEGOTIABLE:** unless asking for blockers or clarifications, before returning to the user, YOU always build and test the code! only return if everything is ok!!
