import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'scripts' / 'probe_deployed_contract.py'
spec = importlib.util.spec_from_file_location('probe_deployed_contract', PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class DeployedInterfaceProbeTests(unittest.TestCase):
    def test_event_signature_identified_in_supplied_receipt(self):
        self.assertEqual(mod.DEPLOYED_EVENT_SIGNATURE, 'InstanceCreated(bytes32,address,uint8)')
        topic0 = bytes.fromhex('b83bd3e1238bd470bced3919e62d0551496003aac4fb9949adffad0e1a6801f5')
        instance_id = '0x' + '55' * 32
        sender = '0x' + 'f4' * 20
        topics = [topic0,bytes.fromhex('55'*32), bytes(12)+bytes.fromhex('f4'*20)]
        result = mod.validate_creation_event(
            topics=topics, data=(1).to_bytes(32,'big'),expected_topic=topic0,
            instance_id=instance_id,expected_creator=sender,
        )
        self.assertTrue(result['instance_matches_journal'])
        self.assertTrue(result['creator_matches_tx_sender'])
        self.assertTrue(result['state_is_active'])
        self.assertEqual(result['state_value'],1)

    def test_event_wrong_topic_or_instance_not_confirmed(self):
        topic0=bytes.fromhex('b83bd3e1238bd470bced3919e62d0551496003aac4fb9949adffad0e1a6801f5')
        args=dict(topics=[topic0,bytes.fromhex('aa'*32),bytes(12)+bytes.fromhex('ab'*20)],
                  data=(1).to_bytes(32,'big'),expected_topic=topic0,
                  instance_id='0x'+'aa'*32,expected_creator='0x'+'ab'*20)
        self.assertIsNone(mod.validate_creation_event(**{**args,'expected_topic':bytes(32)}))
        self.assertFalse(mod.validate_creation_event(**{**args,'instance_id':'0x'+'bb'*32})['instance_matches_journal'])
        self.assertFalse(mod.validate_creation_event(**{**args,'data':(2).to_bytes(32,'big')})['state_is_active'])
        self.assertIsNone(mod.validate_creation_event(**{**args,'data':bytes(31)}))

    def test_push4_ignores_push_data(self):
        self.assertEqual(mod.push4_immediates(bytes.fromhex('63deadbeef60ff63aabbccdd')),
                         {'0xdeadbeef','0xaabbccdd'})
        self.assertEqual(mod.push4_immediates(bytes.fromhex('7f')+bytes.fromhex('63deadbeef')+bytes(27)), set())

    def test_raw_return_preserves_structure_and_matching_commitments(self):
        a=bytes.fromhex('11'*32)
        b=bytes.fromhex('22'*32)
        c=bytes.fromhex('33'*32)
        output=mod.explain_view_return(
            a+b+c+(1).to_bytes(32,'big'),
            {'intent_hash':'0x'+a.hex(),'model_hash':'0x'+b.hex(),'policy_hash':'0x'+c.hex()},
        )
        self.assertEqual(output['word_count'],4)
        self.assertEqual(output['matched_commitment_word_indices'],{'intent_hash':0,'model_hash':1,'policy_hash':2})

if __name__=='__main__':unittest.main()
