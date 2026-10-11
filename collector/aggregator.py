"""
流量聚合器模块
周期性地从抓包引擎取计数器快照，加工成一条条进程流量记录，
写入 SQLite；同时在内存中保留近若干周期数据供实时查询。
"""
import threading
import time
from datetime import datetime, timedelta

from storage import Storage


class Aggregator:
    """周期聚合线程：抓包快照 → 落库 + 内存环形缓冲"""

    def __init__(self, sniffer, pid_mapper, storage: Storage,
                 window_seconds=60, keep_windows=60, rules=None):
        self.sniffer = sniffer
        self.pid_mapper = pid_mapper
        self.storage = storage
        self.window_seconds = window_seconds   # 聚合周期（秒）
        self.keep_windows = keep_windows       # 内存保留近N个周期（供实时面板）
        self.rules = rules                     # 规则引擎引用（第四批接入，先为None）
        self.recent = []                       # [{ts, pid, name, in, out}, ...]
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            # 等一个窗口周期；用 stop.wait 代替 sleep 便于立即退出
            if self._stop.wait(self.window_seconds):
                break
            self._tick()

    def _tick(self):
        """一个聚合周期：取快照 → 落库 → 更新内存缓冲 → 触发规则检查"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        snap = self.sniffer.snapshot()
        if not snap:
            return

        records = []
        for pid, c in snap.items():
            name = self.pid_mapper._get_proc_name(pid)
            records.append((now, pid, name,
                            c["in_bytes"], c["out_bytes"],
                            c["in_pkts"], c["out_pkts"]))
            # 内存缓冲供实时面板（保留原始PID便于前端过滤）
            with self.lock:
                self.recent.append({
                    "ts": now, "pid": pid, "name": name,
                    "in_bytes": c["in_bytes"], "out_bytes": c["out_bytes"],
                })

        # 环形缓冲：只保留最近 keep_windows 个周期
        with self.lock:
            max_len = self.keep_windows * 64  # 粗略上限（每周期最多64进程）
            if len(self.recent) > max_len:
                self.recent = self.recent[-max_len:]

        # 落库（失败不中断采集循环，只打印）
        try:
            self.storage.insert_window(now, records)
        except Exception as e:
            print(f"[aggregator] 落库失败: {e}")

        # 规则检查钩子（第四批接入规则引擎后启用）
        if self.rules is not None:
            self.rules.check_window(now, snap, self.pid_mapper)

    def get_recent(self, minutes=5):
        """返回最近N分钟的实时数据（供IPC服务端）"""
        cutoff = (datetime.now() - timedelta(minutes=minutes)
                  ).strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            # 真正的按时间过滤：只返回窗口内记录
            return [r for r in self.recent if r["ts"] >= cutoff]

    def stop(self):
        self._stop.set()


if __name__ == "__main__":
    # 集成测试：抓包 + 聚合 + 落库 全链路跑30秒
    from pid_mapper import PidMapper
    from sniffer import PacketSniffer

    m = PidMapper(); m.start()
    s = PacketSniffer(m); s.start()
    st = Storage()
    a = Aggregator(s, m, st, window_seconds=10)  # 测试用10秒一个窗口
    a.start()
    print("采集30秒（3个窗口）... 请持续产生流量")
    time.sleep(30)
    a.stop(); s.stop()

    print("\n数据库最近记录:")
    for r in st.query_recent(seconds=120)[:5]:
        print(f"  {r['ts']} {r['proc_name']}: 下{r['in_bytes']}B 上{r['out_bytes']}B")
    print("\n有数据的日期:", st.all_dates())