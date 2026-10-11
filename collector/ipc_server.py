"""
IPC 服务端模块
采集服务与前端界面通过 本地Socket + JSON 文本协议 通信。
协议约定（每个请求一行JSON，响应一行JSON）：
"""
import json
import socket
import threading

IPC_HOST = "127.0.0.1"   # 只监听本机回环地址（安全：外部无法访问）
IPC_PORT = 9527


class IpcServer:
    """TCP Socket服务端：每个连接一个线程，处理JSON请求"""

    def __init__(self, aggregator, storage, rules):
        self.aggregator = aggregator
        self.storage = storage
        self.rules = rules
        self._stop = threading.Event()
        self._thread = None
        self.sock = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((IPC_HOST, IPC_PORT))
        self.sock.listen(8)
        self.sock.settimeout(1)   # 超时1秒以便检查停止标志
        print(f"[ipc] 服务端已启动 {IPC_HOST}:{IPC_PORT}")

        while not self._stop.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        """处理一个连接：逐行读JSON请求 → 路由 → 回JSON响应"""
        conn.settimeout(10)
        try:
            while not self._stop.is_set():
                data = conn.recv(65536)
                if not data:
                    break
                req = json.loads(data.decode("utf-8"))
                resp = self._route(req)
                conn.sendall((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
        except Exception as e:
            print(f"[ipc] 连接异常: {e}")
        finally:
            conn.close()

    def _route(self, req):
        """命令路由表"""
        cmd = req.get("cmd")
        params = req.get("params", {})

        handlers = {
            "get_realtime": self._h_realtime,
            "get_dates": self._h_dates,
            # 修复：用 lambda 把请求参数传进去
            "get_history": lambda: self._h_history(params),
            "get_rules": lambda: self.rules.get_rules(),
            "add_rule": lambda: self.rules.add_rule(
                params.get("proc_name"), params.get("quota_mb"),
                params.get("action", "alert")),
            "remove_rule": lambda: self.rules.remove_rule(params.get("proc_name")),
            "unblock": lambda: self.rules.unblock(params.get("proc_name")),
            "get_alerts": lambda: self.rules.get_alerts(),
            "export_data": lambda: self._h_export(params),
            "get_hourly": lambda: self._h_hourly(params),
        }
        handler = handlers.get(cmd)
        if handler is None:
            return {"errCode": 400, "errMsg": f"未知命令: {cmd}"}
        try:
            return {"errCode": 0, "data": handler()}
        except Exception as e:
            return {"errCode": 500, "errMsg": str(e)}

    # ---------- 各命令处理器 ----------
    def _h_realtime(self):
        return self.aggregator.get_recent()

    def _h_dates(self):
        return self.storage.all_dates()

    def _h_history(self, params):
        date_str = params.get("date", "")
        if not date_str:
            return []
        return self.storage.query_day_summary(date_str)
    def _h_export(self, params):
        date_str = params.get("date", "")
        if not date_str:
            raise ValueError("缺少日期参数")
        return self.storage.export_csv(date_str)

    def _h_hourly(self, params):
        date_str = params.get("date", "")
        if not date_str:
            return []
        return self.storage.query_hourly_trend(date_str)

    def stop(self):
        self._stop.set()
        if self.sock:
            self.sock.close()


if __name__ == "__main__":
    # 独立测试：启动服务端，用一段内嵌客户端代码发请求验证
    import time
    from storage import Storage

    st = Storage()
    # 用一个假聚合器对象（只测IPC通路）
    class FakeAgg:
        def get_recent(self):
            return [{"ts": "2026-09-24 17:00:00", "pid": 1,
                     "name": "test.exe", "in_bytes": 100, "out_bytes": 50}]
    class FakeRules:
        def get_rules(self): return []
        def get_alerts(self): return []
        def add_rule(self, *a, **k): return True
        def remove_rule(self, *a, **k): return True
        def unblock(self, *a, **k): return True

    srv = IpcServer(FakeAgg(), st, FakeRules())
    srv.start()
    time.sleep(1)

    # ---- 测试客户端 ----
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((IPC_HOST, IPC_PORT))
    for req in [
        {"cmd": "get_realtime"},
        {"cmd": "get_dates"},
        {"cmd": "get_history", "params": {"date": "2026-09-24"}},
        {"cmd": "add_rule", "params": {"proc_name": "test.exe",
                                        "quota_mb": 100, "action": "alert"}},
        {"cmd": "get_rules"},
        {"cmd": "bad_cmd"},
    ]:
        c.sendall(json.dumps(req, ensure_ascii=False).encode("utf-8"))
        resp = c.recv(65536).decode("utf-8")
        print(f"请求 {req['cmd']:15s} → {resp}")
    c.close()
    srv.stop()