require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.26",
    settings: {
      "viaIR": true,
      //"evmVersion": "cancun",
      optimizer: {
        enabled: true,
        runs: 100000
      }
    }
  }
};
