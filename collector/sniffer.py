"""
抓包引擎模块
用 scapy 实时抓取经过本机网卡的 IP 数据包，解析出本机端口与流向，
借助 PidMapper 把流量归属到具体进程，按 PID 累计字节数/包数。
"""
import threading
import socket
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP

from pid_mapper import PidMapper  # 同目录下的映射表模块


class PacketSniffer:
    """后台抓包线程：只负责把每个数据包累加到进程计数器"""

    def __init__(self, pid_mapper: PidMapper):
        self.pid_mapper = pid_mapper
        self.lock = threading.Lock()
        # 计数器：pid -> {"in_bytes":, "out_bytes":, "in_pkts":, "out_pkts":}
        self.counters = defaultdict(lambda: {
            "in_bytes": 0, "out_bytes": 0, "in_pkts": 0, "out_pkts": 0
        })
        self.local_ips = self._get_local_ips()
        self._stop = threading.Event()
        self._thread = None

    @staticmethod
    def _get_local_ips():
        """获取本机所有网卡的IPv4地址（用于判断包方向）"""
        ips = set()
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
        ips.add("127.0.0.1")
        return ips

    def start(self):
        """启动抓包线程"""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        """scapy 抓包主循环（阻塞式，放到独立线程）"""
        # store=False 表示不缓存包；filter="ip" 只抓IPv4，过滤本机无关广播
        sniff(prn=self._on_packet, store=False, filter="ip",
              stop_filter=lambda _: self._stop.is_set())

    def _on_packet(self, pkt):
        """每捕获一个包的回调"""
        if IP not in pkt:
            return

        ip = pkt[IP]
        src_ip, dst_ip = ip.src, ip.dst
        proto_layer = pkt[TCP] if TCP in pkt else (pkt[UDP] if UDP in pkt else None)
        if proto_layer is None:
            return  # 非TCP/UDP的IP包（如ICMP）暂不统计

        # ---- 判断方向与本机端口 ----
        # 包的源地址是本机 -> 出站流量，本机端口=源端口
        if src_ip in self.local_ips:
            direction = "out"
            local_port = proto_layer.sport
        # 包的目的地址是本机 -> 入站流量，本机端口=目的端口
        elif dst_ip in self.local_ips:
            direction = "in"
            local_port = proto_layer.dport
        else:
            return  # 本机不参与的流量（如局域网其他设备间通信）丢弃

        # ---- 端口查进程 ----
        hit = self.pid_mapper.lookup(local_port)
        if hit is None:
            return  # 映射表里没有（如映射过期），无法归属，丢弃
        pid, _ = hit

        size = len(pkt)  # 链路层到应用层的完整长度

        # ---- 累加计数（线程安全）----
        with self.lock:
            c = self.counters[pid]
            if direction == "in":
                c["in_bytes"] += size
                c["in_pkts"] += 1
            else:
                c["out_bytes"] += size
                c["out_pkts"] += 1

    def snapshot(self):
        """返回计数器快照并清零（供聚合器周期调用）"""
        with self.lock:
            data = {pid: dict(c) for pid, c in self.counters.items()}
            self.counters.clear()
            return data

    def stop(self):
        """停止抓包"""
        self._stop.set()


if __name__ == "__main__":
    # 独立测试：抓10秒，打印这段时间内产生流量的进程
    import time
    m = PidMapper()
    m.start()
    s = PacketSniffer(m)
    s.start()
    print("抓包中（10秒）... 请打开网页或播放视频产生流量")
    time.sleep(10)
    s.stop()

    snap = s.snapshot()
    if not snap:
        print("未捕获到任何流量（检查是否管理员运行 + Npcap已安装）")
    else:
        for pid, c in sorted(snap.items(),
                              key=lambda x: x[1]["in_bytes"] + x[1]["out_bytes"],
                              reverse=True)[:10]:
            name = m._get_proc_name(pid)
            total = c["in_bytes"] + c["out_bytes"]
            print(f"{name}(PID {pid}): 下行{c['in_bytes']}B 上行{c['out_bytes']}B 共{total}B")