const {assertEqualBN} = require("./helper/assert");
const {
    advanceBlockAndSetTime,
    bufToStr,
    depositHtlcArrayToObj,
    getBalance,
    isSha256Hash,
    newSecretHashPair,
    nowSeconds,
    random32,
    sleep,
    txContractId,
    txLoggedArgs,
    txGas
} = require("./helper/utils");

const DepositHashedTimelock = artifacts.require('./DepositHashedTimelock.sol')

const REQUIRE_FAILED_MSG = 'Returned error: VM Exception while processing transaction: revert'

const hourSeconds = 3600
const timeLock1Hour = nowSeconds() + hourSeconds
const oneFinney = web3.utils.toWei(web3.utils.toBN(1), 'finney')

contract('DepositHashedTimelock', accounts => {
    const owner = accounts[0]
    const sender = accounts[1]
    const receiver = accounts[2]

    it('newContract() should create new contract and store correct details', async () => {
        const hashPair = newSecretHashPair()
        const htlc = await DepositHashedTimelock.deployed()
        const txReceipt = await htlc.newContract(
            receiver,
            hashPair.hash,
            timeLock1Hour,
            {
                from: sender,
                value: oneFinney,
            }
        )
        const logArgs = txLoggedArgs(txReceipt)

        const contractId = logArgs.contractId
        assert(isSha256Hash(contractId))

        assert.equal(logArgs.sender, sender)
        assert.equal(logArgs.receiver, receiver)
        assertEqualBN(logArgs.amount, oneFinney)
        assert.equal(logArgs.hashlock, hashPair.hash)
        assert.equal(logArgs.timelock, timeLock1Hour)

        const contractArr = await htlc.getContract.call(contractId)
        const contract = depositHtlcArrayToObj(contractArr)
        assert.equal(contract.sender, sender)
        assert.equal(contract.receiver, receiver)
        assertEqualBN(contract.amount, oneFinney)
        assertEqualBN(contract.refundAmount, oneFinney)
        assert.equal(contract.hashlock, hashPair.hash)
        assert.equal(contract.timelock.toNumber(), timeLock1Hour)
        assert.isFalse(contract.withdrawn)
        assert.isFalse(contract.refunded)
        assert.equal(
            contract.preimage,
            '0x0000000000000000000000000000000000000000000000000000000000000000'
        )
    })

    it('newContract() should fail when no ETH sent', async () => {
        const hashPair = newSecretHashPair()
        const htlc = await DepositHashedTimelock.deployed()
        try {
            await htlc.newContract(receiver, hashPair.hash, timeLock1Hour, {
                from: sender,
                value: 0,
            })
            assert.fail('expected failure due to 0 value transferred')
        } catch (err) {
            assert.isTrue(err.message.startsWith(REQUIRE_FAILED_MSG))
        }
    })

    it('newContract() should fail with timelocks in the past', async () => {
        const hashPair = newSecretHashPair()
        const pastTimelock = nowSeconds() - 1
        const htlc = await DepositHashedTimelock.deployed()
        try {
            await htlc.newContract(receiver, hashPair.hash, pastTimelock, {
                from: sender,
                value: oneFinney,
            })

            assert.fail('expected failure due past timelock')
        } catch (err) {
            assert.isTrue(err.message.startsWith(REQUIRE_FAILED_MSG))
        }
    })

    it('newContract() should reject a duplicate contract request', async () => {
        const hashPair = newSecretHashPair()
        const htlc = await DepositHashedTimelock.deployed()
        await htlc.newContract(receiver, hashPair.hash, timeLock1Hour, {
            from: sender,
            value: oneFinney,
        })

        // now call again with the exact same parameters
        try {
            await htlc.newContract(receiver, hashPair.hash, timeLock1Hour, {
                from: sender,
                value: oneFinney,
            })
            assert.fail('expected failure due to duplicate request')
        } catch (err) {
            assert.isTrue(err.message.startsWith(REQUIRE_FAILED_MSG))
        }
    })

    it('withdraw() should send receiver funds when given the correct secret preimage before timelock expires', async () => {
        const hashPair = newSecretHashPair()
        const htlc = await DepositHashedTimelock.deployed()
        const newContractTx = await htlc.newContract(
            receiver,
            hashPair.hash,
            timeLock1Hour,
            {
                from: sender,
                value: oneFinney,
            }
        )

        const contractId = txContractId(newContractTx)
        const receiverBalBefore = await getBalance(receiver)

        // receiver calls withdraw with the secret to get the funds
        const withdrawTx = await htlc.withdraw(contractId, hashPair.secret, {
            from: receiver,
        })
        const tx = await web3.eth.getTransaction(withdrawTx.tx)

        // Check contract funds are now at the receiver address
        const expectedBal = receiverBalBefore
            .add(oneFinney)
            .sub(txGas(withdrawTx, tx.gasPrice))
        assertEqualBN(
            await getBalance(receiver),
            expectedBal,
            "receiver balance doesn't match"
        )
        const contractArr = await htlc.getContract.call(contractId)
        const contract = depositHtlcArrayToObj(contractArr)
        assert.isTrue(contract.withdrawn) // withdrawn set
        assert.isFalse(contract.refunded) // refunded still false
        assert.equal(contract.preimage, hashPair.secret)
    })

    it('withdraw() should send receiver funds when given the correct secret preimage after timelock expires', async () => {
        const now = nowSeconds()
        const hashPair = newSecretHashPair()
        const htlc = await DepositHashedTimelock.deployed()
        const timelock1Second = now + 1

        await advanceBlockAndSetTime(now - 1)

        const newContractTx = await htlc.newContract(
            receiver,
            hashPair.hash,
            timelock1Second,
            {
                from: sender,
                value: oneFinney,
            }
        )

        const contractId = txContractId(newContractTx)

        // wait two seconds so we move past the timelock time
        await sleep(2000)
        await advanceBlockAndSetTime(now + 2)

        const receiverBalBefore = await getBalance(receiver)

        // receiver calls withdraw with the secret to get the funds
        const withdrawTx = await htlc.withdraw(contractId, hashPair.secret, {
            from: receiver,
        })
        const tx = await web3.eth.getTransaction(withdrawTx.tx)

        // Check contract funds are now at the receiver address
        const expectedBal = receiverBalBefore
            .add(oneFinney)
            .sub(txGas(withdrawTx, tx.gasPrice))
        assertEqualBN(
            await getBalance(receiver),
            expectedBal,
            "receiver balance doesn't match"
        )
        const contractArr = await htlc.getContract.call(contractId)
        const contract = depositHtlcArrayToObj(contractArr)
        assert.isTrue(contract.withdrawn) // withdrawn set
        assert.isFalse(contract.refunded) // refunded still false
        assert.equal(contract.preimage, hashPair.secret)
    })

    it('withdraw() should fail if preimage does not hash to hashX', async () => {
        const hashPair = newSecretHashPair()
        const htlc = await DepositHashedTimelock.deployed()
        const newContractTx = await htlc.newContract(
            receiver,
            hashPair.hash,
            timeLock1Hour,
            {
                from: sender,
                value: oneFinney,
            }
        )
        const contractId = txContractId(newContractTx)

        // receiver calls withdraw with an invalid secret
        const wrongSecret = bufToStr(random32())
        try {
            await htlc.withdraw(contractId, wrongSecret, {from: receiver})
            assert.fail('expected failure due to 0 value transferred')
        } catch (err) {
            assert.isTrue(err.message.startsWith(REQUIRE_FAILED_MSG))
        }
    })

    it('withdraw() should fail if caller is not the receiver', async () => {
        const hashPair = newSecretHashPair()
        const htlc = await DepositHashedTimelock.deployed()
        const newContractTx = await htlc.newContract(
            receiver,
            hashPair.hash,
            timeLock1Hour,
            {
                from: sender,
                value: oneFinney,
            }
        )
        const contractId = txContractId(newContractTx)
        const someGuy = accounts[4]
        try {
            await htlc.withdraw(contractId, hashPair.secret, {from: someGuy})
            assert.fail('expected failure due to wrong receiver')
        } catch (err) {
            assert.isTrue(err.message.startsWith(REQUIRE_FAILED_MSG))
        }
    })

    it('refund() should pass after timelock expiry', async () => {
        const now = nowSeconds()
        const hashPair = newSecretHashPair()
        const htlc = await DepositHashedTimelock.deployed()
        const timelock1Second = now + 1

        await advanceBlockAndSetTime(now - 1)

        const newContractTx = await htlc.newContract(
            receiver,
            hashPair.hash,
            timelock1Second,
            {
                from: sender,
                value: oneFinney,
            }
        )
        const contractId = txContractId(newContractTx)

        // wait one second so we move past the timelock time
        await sleep(1000)
        await advanceBlockAndSetTime(now + 1)

        const balBefore = await getBalance(sender)
        const refundTx = await htlc.refund(contractId, {from: sender})
        const tx = await web3.eth.getTransaction(refundTx.tx)
        // Check contract funds are now at the senders address
        const expectedBal = balBefore.add(oneFinney).sub(txGas(refundTx, tx.gasPrice))
        assertEqualBN(
            await getBalance(sender),
            expectedBal,
            "sender balance doesn't match"
        )
        const contractArr = await htlc.getContract.call(contractId)
        const contract = depositHtlcArrayToObj(contractArr)
        assert.isFalse(contract.withdrawn)
        assert.isTrue(contract.refunded)
    })

    it('refund() should fail before the timelock expiry', async () => {
        const hashPair = newSecretHashPair()
        const htlc = await DepositHashedTimelock.deployed()
        const newContractTx = await htlc.newContract(
            receiver,
            hashPair.hash,
            timeLock1Hour,
            {
                from: sender,
                value: oneFinney,
            }
        )
        const contractId = txContractId(newContractTx)
        try {
            await htlc.refund(contractId, {from: sender})
            assert.fail('expected failure due to timelock')
        } catch (err) {
            assert.isTrue(err.message.startsWith(REQUIRE_FAILED_MSG))
        }
    })

    it("getContract() returns empty record when contract doesn't exist", async () => {
        const htlc = await DepositHashedTimelock.deployed()
        const contract = await htlc.getContract.call('0xabcdef')
        const sender = contract[0]
        assert.equal(Number(sender), 0)
    })

    it('has zero fee after deploy', async () => {
        const htlc = await DepositHashedTimelock.deployed()
        const fee = await htlc.getFee.call()
        assert.equal(fee, 0)
    })

    it("setFee() can set the fee and then set it back to zero", async () => {
        const htlc = await DepositHashedTimelock.deployed()
        const setFee = oneFinney
        const zeroFee = 0

        await htlc.setFee(setFee)

        const actualFee = await htlc.getFee.call()
        assertEqualBN(actualFee, setFee)

        await htlc.setFee(zeroFee)

        const actualZeroFee = await htlc.getFee.call()
        assertEqualBN(actualZeroFee, zeroFee)
    })

    it('setFee() requires owner', async () => {
        const htlc = await DepositHashedTimelock.deployed()

        try {
            await htlc.setFee(oneFinney, {from: sender})
            assert.fail('expected failure due to invalid user')
        } catch (err) {
            assert.isTrue(err.message.includes('Ownable: caller is not the owner'))
        }
    })

    it('collectFee() requires some accumulated fees before', async () => {
        const htlc = await DepositHashedTimelock.deployed()

        try {
            await htlc.collectFee(sender, {from: owner})
            assert.fail('expected failure due to no fee collected')
        } catch (err) {
            assert.isTrue(err.message.includes('No fee has been collected'))
        }
    })

    it('collectFee() requires owner', async () => {
        const htlc = await DepositHashedTimelock.deployed()

        try {
            await htlc.collectFee(sender, {from: sender})
            assert.fail('expected failure due to invalid user')
        } catch (err) {
            assert.isTrue(err.message.includes('Ownable: caller is not the owner'))
        }
    })

    describe("with fee", () => {
        it('newContract() should create new contract with the current fee value', async () => {
            const setFee = web3.utils.toWei('0.0004')
            const hashPair = newSecretHashPair()
            const htlc = await DepositHashedTimelock.deployed()

            await htlc.setFee(setFee)

            const txReceipt = await htlc.newContract(
                receiver,
                hashPair.hash,
                timeLock1Hour,
                {
                    from: sender,
                    value: oneFinney,
                }
            )
            const logArgs = txLoggedArgs(txReceipt)

            const contractId = logArgs.contractId
            assert(isSha256Hash(contractId))

            const contractArr = await htlc.getContract.call(contractId)
            const contract = depositHtlcArrayToObj(contractArr)
            assertEqualBN(contract.amount, oneFinney)
            assertEqualBN(contract.refundAmount, oneFinney - setFee)
        })

        it('newContract() should reject too low amount', async () => {
            const setFee = 2 * oneFinney
            const hashPair = newSecretHashPair()
            const htlc = await DepositHashedTimelock.deployed()

            await htlc.setFee(setFee)

            try {
                await htlc.newContract(receiver, hashPair.hash, timeLock1Hour, {
                    from: sender,
                    value: oneFinney,
                })

                assert.fail('expected failure due too low amount')
            } catch (err) {
                assert.isTrue(err.message.startsWith(REQUIRE_FAILED_MSG))
            }
        })

        it('withdraw() should send receiver funds with the fee', async () => {
            const setFee = web3.utils.toWei('0.0004')
            const hashPair = newSecretHashPair()
            const htlc = await DepositHashedTimelock.deployed()

            await htlc.setFee(setFee)

            const newContractTx = await htlc.newContract(
                receiver,
                hashPair.hash,
                timeLock1Hour,
                {
                    from: sender,
                    value: oneFinney,
                }
            )

            const contractId = txContractId(newContractTx)
            const receiverBalBefore = await getBalance(receiver)

            // receiver calls withdraw with the secret to get the funds
            const withdrawTx = await htlc.withdraw(contractId, hashPair.secret, {
                from: receiver,
            })
            const tx = await web3.eth.getTransaction(withdrawTx.tx)

            // Check contract funds are now at the receiver address
            const expectedBal = receiverBalBefore
                .add(oneFinney)
                .sub(txGas(withdrawTx, tx.gasPrice))
            assertEqualBN(
                await getBalance(receiver),
                expectedBal,
                "receiver balance doesn't match"
            )
        })

        it('refund() should send funds back without the fee, then collectFee() can send the fee', async () => {
            const setFee = web3.utils.toBN(web3.utils.toWei('0.0004'))
            const now = nowSeconds()
            const hashPair = newSecretHashPair()
            const htlc = await DepositHashedTimelock.deployed()
            const timelock1Second = now + 1

            await htlc.setFee(setFee)
            await advanceBlockAndSetTime(now - 1)

            const newContractTx = await htlc.newContract(
                receiver,
                hashPair.hash,
                timelock1Second,
                {
                    from: sender,
                    value: oneFinney,
                }
            )
            const contractId = txContractId(newContractTx)

            // wait one second so we move past the timelock time
            await sleep(1000)
            await advanceBlockAndSetTime(now + 1)

            const balBefore = await getBalance(sender)
            const refundTx = await htlc.refund(contractId, {from: sender})
            const tx = await web3.eth.getTransaction(refundTx.tx)
            const gasPrice = tx.gasPrice
            // Check contract funds are now at the senders address
            const expectedBal = balBefore.add(oneFinney).sub(setFee).sub(txGas(refundTx, gasPrice))
            assertEqualBN(
                await getBalance(sender),
                expectedBal,
                "sender balance doesn't match"
            )

            // check collect fee
            const ownBalBefore = await getBalance(owner)
            const collectTx = await htlc.collectFee(owner, {from: owner})
            const ownExpectedBal = ownBalBefore.add(setFee).sub(txGas(collectTx, gasPrice))
            assertEqualBN(
                await getBalance(owner),
                ownExpectedBal,
                "owner balance doesn't match"
            )
        })
    })
})
