# Install

1. Clone the repository.
2. Copy \`hermes-bounty-core\` into your Hermes skills location, or symlink it.
3. Copy the example config files to your project and remove \`.example\`.
4. Fill in program rules and exact scope.
5. Keep cookies/tokens in your existing Burp/session vault. Use opaque IDs in Hermes.
6. Point your existing Burp MCP bridge to the contract in \`interfaces/mcp-contracts.md\`.
7. Initialize a local SQLite database using \`brain/schema.sql\`.
8. Start Hermes from the project directory so \`.hermes.md\` and \`AGENTS.md\` are loaded.
9. Ask Hermes to load the \`hermes-bounty-core\` skill and initialize a target assessment from the supplied program files.

Recommended Hermes delegation:
- max_concurrent_children: 15
- max_spawn_depth: 2
- approvals.mode: smart

Do not disable scope enforcement or approvals globally.