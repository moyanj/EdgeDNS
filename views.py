from typing import Any
from flask import Blueprint, request, current_app, render_template_string, make_response
import ujson
from flask_httpauth import HTTPBasicAuth


# 初始化蓝图
bp = Blueprint("api", __name__)
auth = HTTPBasicAuth()

config = ujson.load(open("data/config.json", "r"))


@auth.verify_password
def verify_password(username, password):
    if username == config["username"] and password == config["password"]:
        return username


def jsonify(data: Any):
    """
    将数据转换为JSON格式并返回
    """
    response = make_response(ujson.dumps(data))
    response.headers["Content-Type"] = "application/json"
    return response


@bp.route("/")
@auth.login_required
def index():
    """API首页，返回所有DNS记录"""
    dns = current_app.config["dns"]
    records = dns.get_records()
    return render_template_string(
        open("static/index.html", "r").read(), records=records
    )


@bp.route("/api/add", methods=["POST"])
@auth.login_required
def add():
    """添加DNS记录"""
    dns = current_app.config["dns"]
    data = request.get_json()

    # 检查请求是否包含JSON数据
    if not data:
        return (
            jsonify({"code": 400, "msg": "Invalid request: No JSON data provided"}),
            400,
        )

    # 提取必要字段
    required_fields = {"domain", "type", "value"}
    if not required_fields.issubset(set(data.keys())):
        return (
            jsonify({"code": 400, "msg": "Invalid request: Missing required fields"}),
            400,
        )

    # 获取数据
    domain = data.get("domain")
    record_type = data.get("type")
    record_value = data.get("value")
    ttl = data.get("ttl", 300)
    location = data.get("location", "default")

    if not domain.endswith("."):
        domain += "."

    # 添加记录
    try:
        dns.records.add_record(domain, record_type, record_value, ttl, location)
    except Exception as e:
        return jsonify({"code": 400, "msg": str(e)}), 400
    dns.save_records()
    return jsonify({"code": 201, "msg": "Record added successfully", "data": data}), 201


@bp.route("/api/delete/<domain>/<record_type>", methods=["DELETE"])
@auth.login_required
def delete(domain, record_type):
    """删除DNS记录"""
    dns = current_app.config["dns"]

    # 检查域名和记录类型是否存在
    if not dns.records.domain_exists(
        domain
    ) or record_type not in dns.records.records.get(domain, {}):
        return jsonify({"code": 404, "msg": "Record not found"}), 404
    if not domain.endswith("."):
        domain += "."
    # 删除记录
    dns.records.remove_record(domain, record_type)
    dns.save_records()
    return jsonify({"code": 200, "msg": "Record deleted successfully"})


@bp.route("/api/records")
@auth.login_required
def get_records():
    """获取所有DNS记录"""
    dns = current_app.config["dns"]
    return jsonify(dns.get_records())


@bp.route("/api/countries", methods=["GET"])
def get_countries():
    """获取国家列表"""
    dns = current_app.config["dns"]
    return jsonify(dns.records.xdb.countries)


@bp.route("/api/query", methods=["GET"])
def query():
    dns = current_app.config["dns"]
    domain = request.args["domain"]
    type = request.args["type"]
    ip = request.args.get("ip")
    if not domain.endswith("."):
        domain += "."

    if ip is None:
        ip = request.remote_addr
    location = dns.records.get_records(domain, type, ip)
    return jsonify(location)


@bp.route("/dns-query", methods=["GET"])
def dns_query():
    dns = current_app.config["dns"]
    try:
        # 获取查询参数
        domain = request.args.get("domain")
        if not domain:
            return jsonify({"error": "Missing 'domain' parameter"}), 400

        # 获取查询类型，默认为 A 类型
        qtype = request.args.get("type", "A")

        # 执行查询
        answers = dns.records.get_records(domain, qtype, request.remote_addr)

        # 格式化响应数据
        result = {"query": {"domain": domain, "type": qtype}, "answers": []}

        if qtype == "A":
            result["answers"].append({"type": "A", "address": answers["record"]})
        elif qtype == "AAAA":
            result["answers"].append({"type": "AAAA", "address": answers["record"]})
        elif qtype == "CNAME":
            result["answers"].append({"type": "CNAME", "target": answers["record"]})
        elif qtype == "MX":
            result["answers"].append(
                {
                    "type": "MX",
                    "exchange": answers["record"].split(" ")[1],
                    "priority": answers["record"].split(" ")[0],
                }
            )
        elif qtype == "TXT":
            result["answers"].append({"type": "TXT", "text": answers["record"]})
        else:
            result["answers"].append({"type": qtype, "data": answers["record"]})

        return jsonify(result), 200

    except dns.resolver.NXDOMAIN:
        return jsonify({"error": "Domain not found"}), 404
    except dns.resolver.NoAnswer:
        return jsonify({"error": "No DNS record found for the query"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
