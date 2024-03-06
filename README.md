<p align="center">
  <img
    src="https://pbs.twimg.com/profile_images/1760806246863556609/7KRuH37b_400x400.jpg"
    width="128px;">
</p>

<h1 align="center">DoGClaim</h1>
<p align="center">
  Distribution of Games claim contract
</p>

[![Tests](https://github.com/DoG-Protocol/DoGClaim/actions/workflows/test.yml/badge.svg)](https://github.com/DoG-Protocol/DoGClaim/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/DoG-Protocol/DoGClaim/branch/main/graph/badge.svg?token=2TJ6R1WL0Z)](https://codecov.io/gh/DoG-Protocol/DoGClaim)


## Overview
A `DoGClaim` contract to claim an ERC20 compliant token. Each user can claim with a signature generated off-chain by a trusted authority.

## Setup

### Install global dependencies

Install bun globally
```
curl -fsSL https://bun.sh/install | bash
```

Install Foundry globally
```
curl -L https://foundry.paradigm.xyz | bash
echo 'export PATH="$PATH:/Users/$USER/.foundry/bin"' >> ~/.bash_profile
. ~/.bash_profile
foundryup
```

### Install project dependencies

Install dependencies via `bun`:

```
bun install
```

Install Foundry dependencies with `forge`:

```
forge install
```

## Development

### Linting
Lint via `bun`:

```
bun lint
```

### Testing
Test via `bun`:

```
bun run test
```

Or with `forge`:
```
forge build
forge test
```