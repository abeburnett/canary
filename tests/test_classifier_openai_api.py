"""Offline tests of the backend boundary: request, failure, and wire transport."""
import contextlib
import io
import json
import logging
import os
import traceback
import unittest
from unittest.mock import patch

from canary.classifiers import openai_api

KEY = 'test-only-key-sentinel-not-a-credential'
RAW = '  not a verdict: {broken JSON}\n'


def response():
    return {'status': 'completed', 'error': None, 'incomplete_details': None,
            'output': [{'type': 'reasoning', 'summary': []},
                       {'type': 'message', 'role': 'assistant', 'status': 'completed',
                        'content': [{'type': 'output_text', 'text': RAW[:9]},
                                    {'type': 'output_text', 'text': RAW[9:]}]}]}


class OpenAIBackend(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {'OPENAI_API_KEY': KEY}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        # Any accidental socket use fails before connecting anywhere.
        network = patch('socket.socket', side_effect=AssertionError('Network forbidden'))
        network.start()
        self.addCleanup(network.stop)

    def test_exact_single_request_and_unmodified_raw_text(self):
        calls = []
        def fake(body, headers, timeout_s):
            calls.append((json.loads(body), headers, timeout_s))
            return 200, json.dumps(response()).encode()
        result = openai_api.classify('SYSTEM ONLY', '<fenced>INPUT ONLY</fenced>', 7,
                                    model='caller-model', transport=fake)
        self.assertEqual(result, RAW)
        self.assertEqual(len(calls), 1)
        body, headers, timeout = calls[0]
        self.assertEqual(body, {'model': 'caller-model', 'instructions': 'SYSTEM ONLY',
                                'input': '<fenced>INPUT ONLY</fenced>', 'store': False})
        self.assertNotIn('tools', body)
        self.assertEqual(headers['Authorization'], 'Bearer ' + KEY)
        self.assertEqual(timeout, 7)

    def test_failures_raise_without_partial_text_or_secret_diagnostics(self):
        bad = [b'{', b'\xff', b'null', b'[]', b'{}']
        for field, value in [('status', 'incomplete'), ('status', 'failed'),
                             ('error', {'message': KEY}), ('incomplete_details', {'reason':'max_output_tokens'}),
                             ('output', []), ('output', [None])]:
            data = response(); data[field] = value; bad.append(json.dumps(data).encode())
        for replacement in [None, {'type':'refusal','refusal':KEY},
                            {'type':'output_text','text':None}]:
            data=response(); data['output'][1]['content'].append(replacement)
            bad.append(json.dumps(data).encode())
        data=response(); data['output'][1]['status']='in_progress';bad.append(json.dumps(data).encode())
        data=response(); data['output'].append({'type':'function_call','name':'unexpected'});bad.append(json.dumps(data).encode())
        cases=[(200,body) for body in bad]+[(code,json.dumps(response()).encode()) for code in [201,302,401,429,500]]
        cases += [TimeoutError(KEY), OSError(KEY)]
        output = io.StringIO()
        logger = logging.StreamHandler(output); logging.getLogger().addHandler(logger)
        self.addCleanup(logging.getLogger().removeHandler, logger)
        for case in cases:
            calls=[]
            def fake(*args):
                calls.append(True)
                if isinstance(case, Exception): raise case
                return case
            with self.subTest(case=type(case).__name__), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                with self.assertRaises(RuntimeError) as caught:
                    openai_api.classify('system','fenced',3,model='chosen',transport=fake)
                rendered=''.join(traceback.format_exception(type(caught.exception),caught.exception,caught.exception.__traceback__))
                self.assertNotIn(KEY,rendered)
                self.assertEqual(len(calls),1)
        self.assertEqual(output.getvalue(),'')

    def test_default_transport_posts_once_and_closes_without_redirects(self):
        events=[]
        class FakeResponse:
            status=302
            def read(self): return b'redirect body must not be returned'
        class Connection:
            def __init__(self,host,timeout):events.append(('connect',host,timeout))
            def request(self,method,path,body,headers):events.append(('request',method,path))
            def getresponse(self):return FakeResponse()
            def close(self):events.append(('close',))
        with patch('http.client.HTTPSConnection',Connection):
            with self.assertRaises(RuntimeError):
                openai_api.classify('system','fenced',4,model='chosen')
        self.assertEqual(events,[('connect','api.openai.com',4),
                                 ('request','POST','/v1/responses'),('close',)])
