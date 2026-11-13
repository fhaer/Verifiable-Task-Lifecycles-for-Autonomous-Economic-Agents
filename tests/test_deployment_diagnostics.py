import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'scripts' / 'diagnose_deployment.py'
spec = importlib.util.spec_from_file_location('diagnose_deployment', PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class DiagnosticUnitTests(unittest.TestCase):
    def test_create_input_exact_four_words(self):
        selector = bytes.fromhex('01020304')
        values = [bytes([i]) * 32 for i in (1, 2, 3, 4)]
        self.assertEqual(module.decode_create_input(selector + b''.join(values), selector), [v.hex() for v in values])
        self.assertIsNone(module.decode_create_input(selector + b''.join(values), b'xxxx'))
        self.assertIsNone(module.decode_create_input(selector + b''.join(values) + b'x', selector))
    def test_instance_return_six_words(self):
        raw = (bytes([1]) * 32 + bytes([2]) * 32 + bytes([3]) * 32
               + (1).to_bytes(32, 'big') + (0).to_bytes(32, 'big')
               + bytes(12) + bytes([4]) * 20)
        data = module.decode_instance_return(raw)
        self.assertEqual(data['state'], 1)
        self.assertEqual(data['transition_count'], 0)
        self.assertEqual(data['creator'], '0x' + '04' * 20)
        self.assertIsNone(module.decode_instance_return(raw[:-1]))
    def test_bad_commitment(self):
        with self.assertRaises(ValueError): module.canonical_bytes32('0x01')
        self.assertEqual(module.canonical_bytes32('0x' + 'AA' * 32), 'aa' * 32)

if __name__ == '__main__': unittest.main()

class RuntimeCompatTests(unittest.TestCase):
    def test_push4_detection_skips_push_payloads(self):
        code = bytes.fromhex('600563aabbccdd63deadbeef')
        self.assertEqual(module.push4_immediates(code), {'0xaabbccdd', '0xdeadbeef'})

    def test_push4_in_push32_literal_not_reported(self):
        code = bytes.fromhex('7f') + bytes.fromhex('63deadbeef') + bytes(27)
        self.assertEqual(module.push4_immediates(code), set())

    def test_push4_truncated_not_reported(self):
        self.assertEqual(module.push4_immediates(bytes.fromhex('63ab')), set())

    def test_archive_comparison(self):
        sample = dict(creator='0x' + 'ab' * 20, model_hash='0x' + '12' * 32,
                      policy_hash='0x' + '34' * 32, transition_count=2, state=2)
        archive = dict(creator=sample['creator'].upper(), model_hash=sample['model_hash'],
                       policy_hash=sample['policy_hash'], transition_count=2, final_state=2)
        self.assertTrue(all(module.compare_archived_instance(sample, archive).values()))
        archive['transition_count'] = 1
        self.assertFalse(module.compare_archived_instance(sample, archive)['transition_count'])

    def test_log_summary(self):
        receipt = {'logs':[{'address':'0x' + 'ab' * 20, 'topics':[bytes.fromhex('11'*32)], 'data':b'123'}]}
        result = module.summarize_logs(receipt, '0x' + 'ab' * 20)
        self.assertEqual(result['count'], 1)
        self.assertTrue(result['entries'][0]['same_contract'])
        self.assertEqual(result['entries'][0]['data_byte_length'], 3)
