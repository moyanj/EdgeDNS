import traceback
from typing import Any
from flask import (
    Blueprint,
    request,
    current_app,
    render_template_string,
    make_response,
    Response,
)
import ujson
from loguru import logger
from flask_httpauth import HTTPBasicAuth
from dns import message
from base64 import b64decode

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


@bp.before_request
def before_request():
    if request.headers.get("X-Real-IP"):
        request.remote_addr = request.headers.get("X-Real-IP")


@bp.after_request
def after_request(response):
    logger.debug(
        f'{request.remote_addr} - "{request.method} {request.url}" {response.status_code}'
    )
    return response


@bp.route("/")
@auth.login_required
def index():
    """API首页，返回所有DNS记录"""
    dns = current_app.config["dns"]
    records = dns.get_records()
    with open("static/index.html", "r") as f:
        return render_template_string(f.read(), records=records)


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
    location = request.args.get("location", "default")

    # 检查域名和记录类型是否存在
    if not dns.records.domain_exists(
        domain
    ) or record_type not in dns.records.records.get(domain, {}):
        return jsonify({"code": 404, "msg": "Record not found"}), 404
    if not domain.endswith("."):
        domain += "."
    # 删除记录
    dns.records.remove_record(domain, record_type, location)
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


@bp.route("/dns-query", methods=["GET", "POST"])
def dns_query():
    dnsser = current_app.config["dns"]
    # 解析请求中的 DNS 参数
    try:
        if (
            request.method == "POST"
            and request.headers.get("CONTENT_TYPE") == "application/dns-message"
        ):
            query_message = message.from_wire(request.stream.read())
        else:
            dns_query_data = request.args.get("dns")

            if not dns_query_data:
                return jsonify({"error": "DNS 参数缺失"}), 400
            query_message = message.from_wire(b64decode(dns_query_data))

        response = dnsser.create_response(query_message, request.remote_addr).to_wire()
        return Response(response, mimetype="application/dns-message")

    except Exception as e:
        print(traceback.format_exc())
        # 返回错误响应
        return jsonify({"error": "error"}), 500


@bp.route("/api/status")
def status():
    """
    获取服务器状态
    """
    dns = current_app.config["dns"]
    return jsonify(
        {
            "cache_size": dns.cache.size,
            "cache_max_size": dns.cache.max_size,
            "running": dns.running,
            "num_records": len(dns.records.records),
        }
    )
