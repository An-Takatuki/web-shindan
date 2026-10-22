"""週1回の自動診断を、Windows のタスクスケジューラに登録する・止める。

自動診断(--auto)は、保存した入力で診断し、前回から新しく見つかった問題がある時だけ窓を出す。
"""

import datetime
import json
import os
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape

from . import history

TASK_NAME = "WebShindan_WeeklyCheck"
AUTO_ARG = "--auto"
RUN_TIMEOUT_SEC = 30


def settings_path():
    return os.path.join(history.app_dir(), "schedule.json")


def save_settings(url, folder, php_text, server_type):
    with open(settings_path(), "w", encoding="utf-8") as f:
        json.dump({"url": url, "folder": folder, "php_text": php_text, "server_type": server_type}, f,
                  ensure_ascii=False, indent=1)


def load_settings():
    try:
        with open(settings_path(), encoding="utf-8-sig") as f:  # メモ帳等で直されて BOM が付いても読む
            return json.load(f)
    except (OSError, ValueError):
        return None


def _run(args):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        cp = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=RUN_TIMEOUT_SEC,
                            creationflags=flags)
    except (OSError, subprocess.SubprocessError) as e:
        return False, type(e).__name__
    return cp.returncode == 0, cp.stderr.decode("cp932", errors="replace").strip()


def launch_command():
    """(実行するファイル, 引数)。exe なら exe 自身、開発時は pythonw で main.py を動かす(黒い窓を出さない)。"""
    if getattr(sys, "frozen", False):
        return sys.executable, AUTO_ARG
    exe = sys.executable
    pythonw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    main = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main.py"))
    return (pythonw if os.path.isfile(pythonw) else exe), f'"{main}" {AUTO_ARG}'


def task_xml(command, arguments, start):
    """毎週月曜 10:00。PCが切れていて逃した時は次に起動した時に動かす(StartWhenAvailable)。
    ログオン中だけ動かす(結果の窓を出すため)。ネットが無い時は動かさない。"""
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Webサイト脆弱性かんたん診断: 週1回の自動診断</Description></RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start:%Y-%m-%dT%H:%M:%S}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByWeek><DaysOfWeek><Monday /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>
    </CalendarTrigger>
  </Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{escape(command)}</Command><Arguments>{escape(arguments)}</Arguments></Exec>
  </Actions>
</Task>
"""


def next_monday_10(now=None):
    now = now or datetime.datetime.now()
    day = now.date() + datetime.timedelta(days=(7 - now.weekday()) % 7)
    start = datetime.datetime.combine(day, datetime.time(10, 0))
    return start if start > now else start + datetime.timedelta(days=7)


def register(task_name=TASK_NAME):
    """(成功したか, エラーの文章)。同じ名前があれば上書きする。"""
    command, arguments = launch_command()
    fd, path = tempfile.mkstemp(suffix=".xml")
    try:
        with os.fdopen(fd, "w", encoding="utf-16") as f:
            f.write(task_xml(command, arguments, next_monday_10()))
        return _run(["schtasks", "/Create", "/TN", task_name, "/XML", path, "/F"])
    finally:
        os.remove(path)


def unregister(task_name=TASK_NAME):
    return _run(["schtasks", "/Delete", "/TN", task_name, "/F"])


def is_registered(task_name=TASK_NAME):
    return _run(["schtasks", "/Query", "/TN", task_name])[0]
