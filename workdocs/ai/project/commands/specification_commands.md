# Specification Commands

These commands are related to managing specifications, which are high-level abstractions for complex features.

## `read specification <ref>`
*   **Action:**
    1. Execute `read constitution` to get the configured `<SPECIFICATION_KEY>`.
    2. Look for a `<SPECIFICATION_KEY>_<ref>.md` file in `./workdocs/ai/project/specifications`.
    3. If not found, inform the user.
    4. If found, read it and wait for input.

## `update specification <ref>`
*   **Action:**
    1. Execute `read specification <ref>`.
    2. Update it with the provided input.

## `add specification <description>`
*   **Action:**
    1. Execute `read plan`.
    2. Check for existing similar specifications.
    3. If unique, generate a sequential ID.
    4. Execute `read constitution` to get the configured `<SPECIFICATION_KEY>`.
    5. Create a new specification file in `./workdocs/ai/project/specifications/<SPECIFICATION_KEY>_<ref>.md` using the [Specification Template](../specifications/specification_template.md).
    6. Update the plan to include the new specification, using the configured keys.
