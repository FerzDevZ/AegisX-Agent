---
name: smart-contract-web3-security
description: >-
  Audit EVM Solidity smart contracts for reentrancy, flash loan exploits, integer overflows,
  access control flaws, front-running (MEV), and gas optimizations using Foundry and Slither.
  Use when developing smart contracts, conducting Web3 security audits, or writing Foundry tests.
---

# Web3 & Solidity Smart Contract Security Master

This skill provides an audit framework for verifying decentralized smart contracts against critical EVM vulnerabilities, economic attack vectors, and gas inefficiencies.

---

## 🛡️ Smart Contract Security Vulnerability Hierarchy

```mermaid
graph TD
    Audit[Solidity Contract Under Audit] --> V1[1. Reentrancy & Checks-Effects-Interactions CEI]
    V1 --> V2[2. Access Control: onlyOwner, Ownable2Step, Role RBAC]
    V2 --> V3[3. Oracle Manipulation & Flash Loan Resistance: TWAP / Chainlink]
    V3 --> V4[4. Front-Running & MEV Protection: Commit-Reveal]
    V4 --> V5[5. Gas Optimization: Custom errors, unchecked arithmetic]
```

---

## 🎯 Production Invariants

1. **Checks-Effects-Interactions (CEI)**: Always update internal contract state BEFORE sending ether or calling external contract functions.
2. **Custom Errors over Strings**: Use `error Unauthorized();` instead of `require(msg.sender == owner, "Unauthorized");` to save deployment and execution gas.
3. **Decentralized Oracles**: Never rely on instantaneous Uniswap spot reserves for pricing in collateralized lending pools.

---

## 📋 Prosedur Eksekusi

1. **Rubrik Kerentanan EVM**:
   - Baca [references/evm-vulnerabilities.md](./references/evm-vulnerabilities.md).
2. **Template Reentrancy Guard**:
   - Rujuk [resources/ReentrancyGuard.sol](./resources/ReentrancyGuard.sol).
3. **Audit Static Analysis**:
   - Jalankan `bash skills/smart-contract-web3-security/scripts/check-solidity-security.sh`.