"""
IPC 客户端模块（前端进程用）
把命令封装成函数，通过本地Socket请求采集服务，返回解析后的JSON。
"""
import socket
import json

IPC_HOST = "127.0.0.1"
IPC_PORT = 9527


class IpcClient:
    """与采集服务通信的Socket客户端（每次请求短连接，实现简单）"""

    def __init__(self, host=IPC_HOST, port=IPC_PORT):
        self.host = host
        self.port = port

    def request(self, cmd, params=None):
        """发送一个JSON请求，返回响应字典"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)   # 5秒超时，避免采集服务没启动时前端卡死
        try:
            s.connect((self.host, self.port))
            req = json.dumps({"cmd": cmd, "params": params or {}},
                             ensure_ascii=False)
            s.sendall(req.encode("utf-8"))
            # 循环接收直到换行符（协议约定响应以\n结尾，防止大响应截断）
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            return json.loads(buf.decode("utf-8"))
        except (socket.timeout, ConnectionRefusedError) as e:
            return {"errCode": 500, "errMsg": f"无法连接采集服务: {e}"}
        finally:
            s.close()

    # ---- 便捷封装：前端直接调用这些方法 ----
    def realtime(self):
        r = self.request("get_realtime")
        return r.get("data", []) if r.get("errCode") == 0 else []

    def dates(self):
        r = self.request("get_dates")
        return r.get("data", []) if r.get("errCode") == 0 else []

    def history(self, date_str):
        r = self.request("get_history", {"date": date_str})
        return r.get("data", []) if r.get("errCode") == 0 else []

    def rules(self):
        r = self.request("get_rules")
        return r.get("data", []) if r.get("errCode") == 0 else []

    def add_rule(self, proc_name, quota_mb, action):
        return self.request("add_rule", {"proc_name": proc_name,
                                         "quota_mb": quota_mb,
                                         "action": action})

    def remove_rule(self, proc_name):
        return self.request("remove_rule", {"proc_name": proc_name})

    def unblock(self, proc_name):
        return self.request("unblock", {"proc_name": proc_name})

    def alerts(self):
        r = self.request("get_alerts")
        return r.get("data", []) if r.get("errCode") == 0 else []

    def export_csv(self, date_str):
        r = self.request("export_data", {"date": date_str})
        return r.get("data", "") if r.get("errCode") == 0 else ""

    def hourly_trend(self, date_str):
        r = self.request("get_hourly", {"date": date_str})
        return r.get("data", []) if r.get("errCode") == 0 else []

if __name__ == "__main__":
    # 独立测试（先启动 ipc_server.py）
    c = IpcClient()
    print("日期列表:", c.dates())
    print("规则列表:", c.rules())
    print("告警列表:", c.alerts())