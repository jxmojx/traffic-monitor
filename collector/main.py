"""
采集服务一键启动入口
启动全部后台模块：端口映射 → 抓包引擎 → 聚合器 → 规则引擎 → IPC服务
运行: python main.py   （需管理员权限）
"""
import time

from pid_mapper import PidMapper
from sniffer import PacketSniffer
from aggregator import Aggregator
from storage import Storage
from rules import RulesEngine
from ipc_server import IpcServer


def main():
    print("=== 进程流量监控 · 后台采集服务 ===")
    print("启动顺序: 端口映射 → 抓包引擎 → 聚合器 → 规则引擎 → IPC服务")

    # 1. 端口→PID映射表（后台5秒刷新）
    mapper = PidMapper()
    mapper.start()

    # 2. 抓包引擎（实时捕获网卡流量）
    sniffer = PacketSniffer(mapper)
    sniffer.start()

    # 3. 聚合器（60秒窗口落库 + 内存缓冲 + 规则检查）
    storage = Storage()
    rules = RulesEngine()
    aggregator = Aggregator(sniffer, mapper, storage,
                            window_seconds=60, rules=rules)
    aggregator.start()

    # 4. IPC服务端（等前端连接）
    server = IpcServer(aggregator, storage, rules)
    server.start()

    print("全部模块启动完成，Ctrl+C 优雅退出")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在关闭各模块...")
        server.stop()
        aggregator.stop()
        sniffer.stop()
        mapper.stop()


if __name__ == "__main__":
    main()
