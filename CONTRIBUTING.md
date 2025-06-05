# Contributing to World-Class Authentication

Thank you for considering contributing to our authentication system! This document provides guidelines and instructions to help you contribute effectively.

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct:

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community
- Show empathy towards other community members

## How Can I Contribute?

### Reporting Bugs

Before submitting a bug report:

1. Check the issue tracker to avoid duplicates
2. Ensure the bug is related to the backend code (not your frontend implementation)
3. Collect information about the bug (steps to reproduce, expected vs. actual behavior)

When submitting a bug report, please include:

- A clear, descriptive title
- Detailed steps to reproduce the issue
- Expected and actual behavior
- Environment details (OS, Node.js version, etc.)
- Any relevant logs or screenshots

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- A clear description of the enhancement
- The motivation behind it (why it would be useful)
- Any potential implementation details
- If applicable, examples from other projects

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Run tests: `npm test`
5. Ensure code quality: `npm run lint`
6. Commit your changes using conventional commits (see below)
7. Push to your fork: `git push origin feature/your-feature-name`
8. Create a pull request

## Development Setup

1. Clone the repository

   ```bash
   git clone https://github.com/yourusername/world-class-authentication.git
   cd world-class-authentication
   ```

2. Install dependencies

   ```bash
   npm install
   ```

3. Set up environment variables

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Start development database (using Docker)

   ```bash
   npm run docker:dev
   ```

5. Run database migrations

   ```bash
   npm run db:migrate
   ```

6. Start development server
   ```bash
   npm run dev
   ```

## Coding Standards

### TypeScript

- Use strict TypeScript mode
- Provide proper type definitions
- Avoid using `any` type
- Use interfaces for object shapes

### Code Style

We use ESLint and Prettier to enforce code style:

- Run `npm run lint` to check for issues
- Run `npm run format` to automatically format code

Our style guide includes:

- Use single quotes for strings
- 2 spaces for indentation
- Maximum line length of 100 characters
- Semicolons at the end of statements
- No unused variables or imports

### Testing

- Write tests for all new features and bug fixes
- Maintain or improve code coverage
- Tests should be fast and deterministic
- Use meaningful test descriptions

### Commit Messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types include:

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code changes that neither fix bugs nor add features
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Changes to the build process or auxiliary tools
- `security`: Security-related changes

Examples:

- `feat(auth): add support for WebAuthn authentication`
- `fix(mfa): resolve issue with TOTP verification`
- `docs(readme): update installation instructions`

## Pull Request Process

1. Update documentation if needed
2. Add or update tests as necessary
3. Ensure all tests pass and code quality checks succeed
4. Get at least one code review from a maintainer
5. Once approved, a maintainer will merge your PR

## Security Vulnerabilities

If you discover a security vulnerability, please do NOT open an issue. Email security@example.com instead.

## License

By contributing to this project, you agree that your contributions will be licensed under the project's MIT License.
