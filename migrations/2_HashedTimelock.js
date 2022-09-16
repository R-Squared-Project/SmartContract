const DepositHashedTimelock = artifacts.require('./DepositHashedTimelock.sol')
const WithdrawalHashedTimelock = artifacts.require('./WithdrawalHashedTimelock.sol')

module.exports = function (deployer) {
    deployer.deploy(DepositHashedTimelock)
    deployer.deploy(WithdrawalHashedTimelock)
}
