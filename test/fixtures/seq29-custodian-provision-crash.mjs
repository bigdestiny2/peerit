import {
  provisionPeeritSeq29LocalCustodianKeysFixtureV1
} from '../../scripts/lib/seq29-local-custodian-key-provisioning.mjs'

process.env.PEERIT_SEQ29_CUSTODIAN_PROVISION_FIXTURE_TEST = '1'

const directory = process.argv[2]
provisionPeeritSeq29LocalCustodianKeysFixtureV1({ directory }, {
  fillRandom (output, index) {
    output.fill(index + 17)
  },
  onStage (stage) {
    if (stage === 'AFTER_KEY_1_FSYNC') process.kill(process.pid, 'SIGKILL')
  }
})
