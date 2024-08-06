// SPDX-License-Identifier: MIT

pragma solidity 0.8.26;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract KittyCoin is ERC20 {
    error KittyCoin__OnlyKittyPoolCanMintOrBurn();

    // @audit-info inefficient storage of pool address
    address private pool;

    modifier onlyKittyPool() {
        require(msg.sender == pool, KittyCoin__OnlyKittyPoolCanMintOrBurn());
        _;
    }

    // @audit-medium - pool variable initalization
    constructor(address _pool) ERC20("Kitty Token", "MEOWDY") {
        pool = _pool;
    }

    // @audit-medium - lack of validation
    // @audit-info lack of validation of _amount in mint function
    function mint(address _to, uint256 _amount) external onlyKittyPool {
        _mint(_to, _amount);
    }

    // @audit-medium - lack of validation
    // @audit-info lack of validation of _amount in burn function
    function burn(address _from, uint256 _amount) external onlyKittyPool {
        _burn(_from, _amount);
    }
}

// ✅