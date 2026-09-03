require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

// Replace this string with your MetaMask private key.
// (Remember: Always use a testnet account that doesn't have real funds).
const PRIVATE_KEY = "0xYOUR_TESTNET_PRIVATE_KEY_HERE"; 

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 9999
      },
      evmVersion: "cancun"
    }
  },
  networks: {
    hardhat: {},
    amoy: {
      url: "https://polygon-amoy.g.alchemy.com/v2/alch_qWep3FIFarWxwnnMIIqiT",
      accounts: ['0xYOUR_TESTNET_PRIVATE_KEY_HERE'], // This account will pay for the gas
      gasPrice: "auto"
    }
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  }
};