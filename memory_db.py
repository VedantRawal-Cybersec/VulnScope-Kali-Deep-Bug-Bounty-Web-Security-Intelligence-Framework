from __future__ import annotations

import sqlite3
import time
from pathlib import Path

class MemoryDB:
    def __init__(self, path='reports/output/neural-agent/agent-memory.sqlite3'):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.con = sqlite3.connect(self.path)
        self.con.execute('create table if not exists actions(id integer primary key, ts real, target text, name text, ok integer, score real, summary text)')
        self.con.execute('create table if not exists notes(id integer primary key, ts real, target text, note text)')
        self.con.commit()

    def add_action(self, target, name, ok, score, summary=''):
        self.con.execute('insert into actions(ts,target,name,ok,score,summary) values(?,?,?,?,?,?)', (time.time(), target, name, 1 if ok else 0, float(score), str(summary)[-1500:]))
        self.con.commit()

    def add_note(self, target, note):
        self.con.execute('insert into notes(ts,target,note) values(?,?,?)', (time.time(), target, str(note)))
        self.con.commit()

    def recent_actions(self, target, limit=20):
        cur = self.con.execute('select ts,name,ok,score,summary from actions where target=? order by id desc limit ?', (target, int(limit)))
        return [{'ts': r[0], 'name': r[1], 'ok': bool(r[2]), 'score': r[3], 'summary': r[4]} for r in cur.fetchall()]
