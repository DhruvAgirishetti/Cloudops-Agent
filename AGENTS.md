# Repository Guidelines

## Project Structure & Module Organization

This repository currently has no application source, tests, or asset directories. When introducing code, keep runtime modules under `src/`, automated tests under `tests/`, and checked-in static files under `assets/`. Keep feature-specific code together and avoid committing generated output, dependency caches, or local environment files.

## Build, Test, and Development Commands

No build system or development scripts are configured yet. When adding a toolchain, document its prerequisites and canonical commands here and in the project README. Provide reproducible commands for local development, building, and running the full test suite; prefer repository-defined scripts (for example, `npm run build`) over undocumented machine-specific commands.

## Coding Style & Naming Conventions

No formatter, linter, or language-specific conventions are established yet. Follow the conventions of the chosen language and framework, use consistent indentation, and keep names descriptive. Use `PascalCase` for types, `camelCase` for variables and functions, and lowercase kebab-case for general filenames unless the language ecosystem expects otherwise. Add formatter or linter configuration with the first implementation and apply it consistently.

## Testing Guidelines

There is no test framework or test suite in the repository yet. Add tests alongside the first functional code, using the selected framework's standard discovery pattern (for example, `tests/<feature>.test.<ext>`). Include a documented command that runs all tests, and cover user-visible behavior and important failure cases.

## Commit & Pull Request Guidelines

No Git history or pull request template is available to establish existing conventions. Use short, imperative commit subjects (for example, `Add input validation`). Pull requests should explain the change and its rationale, note how it was verified, link related work when applicable, and include screenshots for user-interface changes.

## Security & Configuration

Keep credentials and machine-specific settings out of version control. Provide safe example configuration with placeholder values and document required environment variables when the application is introduced.
