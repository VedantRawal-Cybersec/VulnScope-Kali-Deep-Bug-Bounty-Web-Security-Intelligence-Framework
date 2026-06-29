from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen

class LLMInterface:
    def __init__(self, provider='none', model='llama3', timeout=30):
        self.provider = provider
        self.model = model
        self.timeout = int(timeout)

    def suggest(self, allowed_actions, target, observed_state, completed):
        if self.provider == 'none':
            return None
        prompt = json.dumps({
            'task': 'choose one next safe review action',
            'allowed_actions': allowed_actions,
            'target': target,
            'observed_state': observed_state,
            'completed': completed,
        })
        text = self._call(prompt)
        for action in allowed_actions:
            if action in text:
                return action
        return None

    def _call(self, prompt):
        if self.provider == 'ollama':
            body = json.dumps({'model': self.model, 'prompt': prompt, 'stream': False}).encode()
            req = Request('http://127.0.0.1:11434/api/generate', data=body, headers={'Content-Type': 'application/json'})
            with urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode('utf-8', errors='ignore')).get('response', '')
        if self.provider == 'openai':
            key = os.environ.get('OPENAI_API_KEY', '')
            if not key:
                return ''
            body = json.dumps({'model': self.model, 'messages': [{'role': 'user', 'content': prompt}], 'temperature': 0.1}).encode()
            req = Request('https://api.openai.com/v1/chat/completions', data=body, headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key})
            with urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode('utf-8', errors='ignore'))
                return data.get('choices', [{}])[0].get('message', {}).get('content', '')
        return ''
