"""
端口 → PID 映射表模块
原理：psutil.net_connections() 提供 (本机地址, 远端地址, 状态, PID) 信息。
抓包只能看到端口，无法直接知道进程；本模块周期刷新"端口→进程"映射，
供聚合器把流量归属到具体进程。
"""
import psutil
import threading
import time


class PidMapper:
    """维护 本地端口 → (pid, 进程名) 的映射表，后台线程周期刷新"""

    def __init__(self, refresh_interval=5.0):
        self.refresh_interval = refresh_interval
        self.lock = threading.Lock()
        # 映射表：{local_port: (pid, proc_name)}
        self.port_map = {}
        # 进程名缓存：{pid: name}，避免频繁查询进程名
        self.name_cache = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._refresh_loop, daemon=True)

    def start(self):
        """启动后台刷新线程"""
        self._thread.start()

    def stop(self):
        """停止刷新线程"""
        self._stop.set()

    def _refresh_loop(self):
        """后台循环：每隔 refresh_interval 秒重建一次映射表"""
        while not self._stop.is_set():
            self.refresh()
            time.sleep(self.refresh_interval)

    def refresh(self):
        """重建端口→PID映射表"""
        new_map = {}
        try:
            # kind='inet' 只看 IPv4 的 TCP+UDP 连接
            for conn in psutil.net_connections(kind='inet'):
                if not conn.laddr or not conn.pid:
                    continue  # 无本地地址或无PID的连接跳过
                port = conn.laddr.port
                pid = conn.pid
                new_map[port] = (pid, self._get_proc_name(pid))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass  # 权限不足或进程已退出的连接忽略
        except Exception as e:
            print(f"[pid_mapper] 刷新失败: {e}")
            return

        with self.lock:
            self.port_map = new_map

    def _get_proc_name(self, pid):
        """获取进程名（带缓存）"""
        if pid in self.name_cache:
            return self.name_cache[pid]
        try:
            name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name = f"unknown({pid})"
        self.name_cache[pid] = name
        return name

    def lookup(self, port):
        """根据本地端口查询 (pid, 进程名)，查不到返回 None"""
        with self.lock:
            return self.port_map.get(port)


if __name__ == "__main__":
    # 独立测试：运行几秒打印当前端口占用情况
    m = PidMapper()
    m.refresh()
    print(f"当前映射到 {len(m.port_map)} 个端口：")
    for port, (pid, name) in list(m.port_map.items())[:20]:
        print(f"  端口 {port} -> {name} (PID {pid})")