"""
规则引擎模块
支持针对单个进程配置流量配额；聚合周期结束时检查是否超额；
超额后执行动作：告警（记录+日志）或控制（Windows防火墙阻断该进程出站）。
"""
import subprocess
import threading
import time
from datetime import datetime

import psutil


class Rule:
    """一条配额规则"""
    def __init__(self, proc_name, quota_bytes, action="alert", enabled=True):
        self.proc_name = proc_name      # 进程名（如 chrome.exe）
        self.quota_bytes = quota_bytes  # 配额（字节），-1 表示不限
        self.action = action            # 超配额动作: "alert" 告警 / "block" 断网
        self.enabled = enabled          # 规则开关


class RulesEngine:
    """规则管理与检查"""

    def __init__(self):
        self.rules = {}                 # proc_name -> Rule
        self.alerts = []                # 告警历史 [{ts, proc_name, message, level}]
        self.usage = {}                 # proc_name -> 当日累计字节
        self.lock = threading.Lock()

    # ---------- 规则管理 ----------
    def add_rule(self, proc_name, quota_mb, action="alert"):
        with self.lock:
            self.rules[proc_name] = Rule(proc_name, int(quota_mb) * 1024 * 1024, action)
        return True

    def remove_rule(self, proc_name):
        with self.lock:
            self.rules.pop(proc_name, None)
        return True

    def get_rules(self):
        with self.lock:
            return [{"proc_name": r.proc_name,
                     "quota_mb": round(r.quota_bytes / 1024 / 1024, 1),
                     "action": r.action, "enabled": r.enabled}
                    for r in self.rules.values()]

    def get_alerts(self):
        with self.lock:
            return list(self.alerts)

    # ---------- 周期检查（聚合器每窗口调用） ----------
    def check_window(self, ts, snapshot, pid_mapper):
        """
        snapshot: {pid: {in_bytes, out_bytes, ...}}
        1. 累计各进程当日用量
        2. 检查是否超配额，超了按规则动作执行
        """
        with self.lock:
            for pid, c in snapshot.items():
                name = pid_mapper._get_proc_name(pid)
                total = c["in_bytes"] + c["out_bytes"]
                self.usage[name] = self.usage.get(name, 0) + total

            for name, rule in self.rules.items():
                if not rule.enabled or rule.quota_bytes < 0:
                    continue
                used = self.usage.get(name, 0)
                if used > rule.quota_bytes and name not in self._blocked_names():
                    self._fire(ts, name, used, rule)

    def _blocked_names(self):
        """当前已被防火墙阻断的进程集合（防止重复添加规则）"""
        return {a["proc_name"] for a in self.alerts
                if a.get("action") == "block"}

    def _fire(self, ts, name, used, rule):
        """执行超配额动作"""
        msg = (f"进程 {name} 当日流量 {used/1024/1024:.1f}MB "
               f"超过配额 {rule.quota_bytes/1024/1024:.1f}MB")
        print(f"[rules] {msg}")

        if rule.action == "block":
            success = self._block_by_firewall(name)
            if success:
                msg += "，已通过防火墙阻断其网络访问"
            else:
                msg += "，防火墙阻断失败（检查管理员权限）"
        self.alerts.append({
            "ts": ts, "proc_name": name, "message": msg,
            "level": "warning", "action": rule.action,
        })

    # ---------- 防火墙控制（Windows netsh 命令） ----------
    @staticmethod
    def _find_exe_path(name):
        """根据进程名查它的可执行文件完整路径（防火墙规则需要）"""
        for proc in psutil.process_iter(["name", "exe"]):
            try:
                if proc.info["name"] == name and proc.info["exe"]:
                    return proc.info["exe"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    def _block_by_firewall(self, name):
        """为该进程添加出站阻断防火墙规则，并强制断开其已有TCP连接"""
        exe = self._find_exe_path(name)
        if not exe:
            return False
        rule_name = f"TM_Block_{name.replace('.exe', '')}"
        # 1. 添加防火墙规则（阻断新建连接）
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=out", f"program={exe}",
             "action=block", "enable=yes"],
            capture_output=True, text=True)
        if result.returncode != 0:
            return False
        # 2. 强制关闭该进程所有已有TCP连接（否则已建立的连接还能继续用）
        pids = [p.pid for p in psutil.process_iter(["name"])
                if p.info["name"] == name]
        for pid in pids:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-NetTCPConnection -OwningProcess {pid} | "
                 f"Remove-NetTCPConnection -Confirm:$false"],
                capture_output=True, text=True)
        return True

    def unblock(self, name):
        """解除防火墙阻断"""
        rule_name = f"TM_Block_{name.replace('.exe', '')}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={rule_name}"],
            capture_output=True, text=True)


if __name__ == "__main__":
    # 独立测试：规则管理（不触发防火墙，只测配额判定逻辑）
    r = RulesEngine()
    r.add_rule("test.exe", quota_mb=1, action="alert")
    print("规则列表:", r.get_rules())

    # 模拟一个窗口的快照：test.exe 用了 1.5MB（超1MB配额）
    from types import SimpleNamespace
    fake_mapper = SimpleNamespace(
        _get_proc_name=lambda pid: "test.exe")
    snap = {999: {"in_bytes": 800 * 1024, "out_bytes": 700 * 1024,
                  "in_pkts": 10, "out_pkts": 10}}
    r.check_window("2026-09-24 17:00:00", snap, fake_mapper)
    print("告警列表:", r.get_alerts())