"""
持久化模块
把聚合器产出的每周期流量数据写入本地 SQLite 数据库，
并提供历史某天 / 实时窗口的查询接口（供前端调用）。
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "traffic.db")


class Storage:
    """SQLite 存储层：建表、写入、按日期/时间范围查询"""

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        """每次操作新建连接（多线程安全）"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # 让查询结果支持按列名取值
        return conn

    def _init_db(self):
        """建表 + 建索引（首次运行自动创建）"""
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          TEXT NOT NULL,   -- 'YYYY-MM-DD HH:MM:SS'
                    pid         INTEGER NOT NULL,
                    proc_name   TEXT NOT NULL,
                    in_bytes    INTEGER DEFAULT 0,
                    out_bytes   INTEGER DEFAULT 0,
                    in_pkts     INTEGER DEFAULT 0,
                    out_pkts    INTEGER DEFAULT 0
                );
                -- 按时间查询是最高频操作（历史某天可视化）
                CREATE INDEX IF NOT EXISTS idx_ts  ON traffic_stats(ts);
                -- 按进程查历史也常用
                CREATE INDEX IF NOT EXISTS idx_pid ON traffic_stats(pid, ts);
            """)

    def insert_window(self, ts, records):
        """
        写入一个聚合周期的数据
        ts: 'YYYY-MM-DD HH:MM:SS' 字符串
        records: [(pid, proc_name, in_bytes, out_bytes, in_pkts, out_pkts), ...]
        """
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO traffic_stats
                   (ts, pid, proc_name, in_bytes, out_bytes, in_pkts, out_pkts)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                records
            )

    def query_by_date(self, date_str):
        """
        查询某一天所有流量记录
        date_str: 'YYYY-MM-DD'
        返回 [{ts, pid, proc_name, in_bytes, out_bytes, ...}, ...]
        """
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT ts, pid, proc_name, in_bytes, out_bytes,
                          in_pkts, out_pkts
                   FROM traffic_stats
                   WHERE ts LIKE ?
                   ORDER BY ts ASC""",
                (date_str + "%",)
            ).fetchall()
        return [dict(r) for r in rows]

    def query_day_summary(self, date_str):
        """
        按天聚合：每个进程当天总流量（供"历史某天Top应用"饼图）
        返回 [{proc_name, in_bytes, out_bytes}, ...] 按总量降序
        """
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT proc_name,
                          SUM(in_bytes)  AS in_bytes,
                          SUM(out_bytes) AS out_bytes
                   FROM traffic_stats
                   WHERE ts LIKE ?
                   GROUP BY proc_name
                   ORDER BY (SUM(in_bytes) + SUM(out_bytes)) DESC""",
                (date_str + "%",)
            ).fetchall()
        return [dict(r) for r in rows]

    def query_recent(self, seconds=300):
        """
        查询最近N秒的数据（供实时面板）
        按 ts 升序返回
        """
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT ts, pid, proc_name, in_bytes, out_bytes
                   FROM traffic_stats
                   WHERE ts >= datetime('now', 'localtime', ?)
                   ORDER BY ts ASC""",
                (f"-{seconds} seconds",)
            ).fetchall()
        return [dict(r) for r in rows]

    def all_dates(self):
        """返回有数据的全部日期列表（供历史查询日期选择器）"""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT DISTINCT substr(ts, 1, 10) AS d
                   FROM traffic_stats ORDER BY d DESC"""
            ).fetchall()
        return [r["d"] for r in rows]

    def export_csv(self, date_str):
        """导出某天全部流量明细为CSV文本（供前端下载）"""
        import csv
        import io
        rows = self.query_by_date(date_str)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["时间", "进程名", "下行字节", "上行字节",
                         "下行包数", "上行包数"])
        for r in rows:
            writer.writerow([r["ts"], r["proc_name"], r["in_bytes"],
                             r["out_bytes"], r["in_pkts"], r["out_pkts"]])
        return buf.getvalue()

    def query_hourly_trend(self, date_str):
        """
        按小时聚合某天流量（供"当日24小时趋势"折线图）
        返回 [{hour, in_bytes, out_bytes}, ...] 按小时升序
        """
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT substr(ts, 12, 2) AS hour,
                          SUM(in_bytes)  AS in_bytes,
                          SUM(out_bytes) AS out_bytes
                   FROM traffic_stats
                   WHERE ts LIKE ?
                   GROUP BY hour
                   ORDER BY hour ASC""",
                (date_str + "%",)
            ).fetchall()
        return [dict(r) for r in rows]

if __name__ == "__main__":
    # 独立测试：插入两条假数据并查询
    s = Storage()
    s.insert_window("2026-09-24 10:00:00", [
        (1234, "test.exe", 1000, 500, 10, 5),
        (5678, "demo.exe", 200, 300, 2, 3),
    ])
    print("按天汇总:", s.query_day_summary("2026-09-24"))
    print("有数据的日期:", s.all_dates())