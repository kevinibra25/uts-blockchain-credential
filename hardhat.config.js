require("@nomicfoundation/hardhat-toolbox");

/** Local development chain saja (tanpa mainnet, tanpa private key pribadi). */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
};
