> [!CAUTION]
> These contracts are currently undergoing security audit. Do not use in production until the audit is complete.


# Modular Smart Account

These contracts define a new smart wallet built to take advantage of recent Ethereum Improvement Proposals (EIPs). Most notably, this is the first implementation of a smart contract to our knowledge with native, combined support for ERC-7702 and ERC-7579.

The implementation aims to be minimal and unopinionated, delegating most smart functionality to ERC-7579 and ERC-7780 modules.

## Feature Highlights

This implementation aims to be fully compatible with the following EIPs.

| ERC | Description |
|-----|-------------|
| [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) | The current standard for Account Abstraction. |
| [ERC-7702](https://eips.ethereum.org/EIPS/eip-7702) | Allowing EOAs to "directly" execute user operations as smart contracts. |
| [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) | Modular account architecture for flexible smart account functionality. |
| [ERC-7484](https://eips.ethereum.org/EIPS/eip-7484) | ERC-7579 extension for optionally using trusted registries for ERC-7579 modules. |
| [ERC-7780](https://eips.ethereum.org/EIPS/eip-7780) | ERC-7579 extension for new, lighter module types such as Policy. |
| [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) | Support for authorization by external smart contracts. |
| [ERC-7739](https://eips.ethereum.org/EIPS/eip-7739) | Hardening against replay attacks in multi-account and cross-chain scenarios. |

## Addresses

On all supported chains:

- Implementation: TODO
- Factory: TODO

Note: This smart contract requires Entrypoint v0.8, which is the first version to natively support ERC-7702.

- Entrypoint v0.8: `0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108`

Supported Chains:

- Base Sepolia

TODO: additional deployments post audit.

To request deployment to an additional chain, please create a Github issue.

## Building

This project uses Foundry.

```bash
forge install
forge build
```

## Benchmarks

TODO: add to github.com/zerodevapp/aa-benchmark post audit

## Contributing

Contributions are welcome, but please open an issue before making any nontrivial PRs.

## Acknowledgements

This project builds on or was aided by the following OSS projects:

- Eth-Infinitism's [reference ERC-7702 smart wallet](https://github.com/eth-infinitism/account-abstraction):
- [ERC-7579 reference implementation](https://github.com/erc7579/erc7579-implementation)
- Rhinestone's and Biconomy's [smartsessions library](https://github.com/erc7579/smartsessions)
- OpenZeppelin's [contract library](https://docs.openzeppelin.com/contracts/5.x)
- Vectorized's [Solady](https://vectorized.github.io/solady/#/), a collection of optimized Solidity snippets.
