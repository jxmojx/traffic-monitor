"""
前端展示界面入口（Flask）
职责：1) 提供网页页面  2) 提供 /api/* 接口（内部转调采集服务的Socket）
运行: python app.py 后浏览器访问 http://127.0.0.1:5000
"""
from flask import Flask, render_template, request, jsonify, Response
from ipc_client import IpcClient

app = Flask(__name__)
ipc = IpcClient()


@app.route("/")
def index():
    """主页面（含实时/历史/规则/告警四个Tab）"""
    return render_template("index.html")


# ---------- API：前端JS通过fetch调用这些接口 ----------

@app.route("/api/realtime")
def api_realtime():
    return jsonify(ipc.realtime())


@app.route("/api/dates")
def api_dates():
    return jsonify(ipc.dates())


@app.route("/api/history")
def api_history():
    date_str = request.args.get("date", "")
    return jsonify(ipc.history(date_str))


@app.route("/api/rules", methods=["GET", "POST"])
def api_rules():
    if request.method == "GET":
        return jsonify(ipc.rules())
    # POST：添加规则 {"proc_name": "...", "quota_mb": 100, "action": "alert"}
    body = request.get_json() or {}
    result = ipc.add_rule(body.get("proc_name"), body.get("quota_mb"),
                          body.get("action", "alert"))
    return jsonify(result)


@app.route("/api/rules/delete", methods=["POST"])
def api_rules_delete():
    body = request.get_json() or {}
    return jsonify(ipc.remove_rule(body.get("proc_name")))


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    body = request.get_json() or {}
    return jsonify(ipc.unblock(body.get("proc_name")))


@app.route("/api/alerts")
def api_alerts():
    return jsonify(ipc.alerts())
@app.route("/api/export")
def api_export():
    """导出某天流量明细为CSV文件下载"""
    date_str = request.args.get("date", "")
    csv_text = ipc.export_csv(date_str)
    if not csv_text:
        return jsonify({"errCode": 500, "errMsg": "导出失败，无该日数据"})
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename=traffic_{date_str}.csv"}
    )

@app.route("/api/hourly")
def api_hourly():
    date_str = request.args.get("date", "")
    return jsonify(ipc.hourly_trend(date_str))

if __name__ == "__main__":
    print("前端界面: http://127.0.0.1:5000  (请确保采集服务已启动)")
    app.run(host="127.0.0.1", port=5000, debug=False)