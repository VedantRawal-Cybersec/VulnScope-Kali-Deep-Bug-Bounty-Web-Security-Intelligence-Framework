class ThoughtLogger:
    def __init__(self, path='reports/output/neural-agent/thinking-log.md'):
        self.path = path
    def log(self, phase, message, data=None):
        import time, json, pathlib
        pathlib.Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, 'a', encoding='utf-8') as f:
            f.write('\n## ' + time.strftime('%Y-%m-%d %H:%M:%S') + ' - ' + str(phase) + '\n\n' + str(message) + '\n')
            if data is not None:
                f.write('\n```json\n' + json.dumps(data, indent=2) + '\n```\n')
        print('[' + str(phase) + '] ' + str(message))
