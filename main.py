from dnsserver import DNSServer
from threading import Thread
from flask import Flask
from views import bp
import os
from loguru import logger
from logging import getLogger

logger.remove()
os.makedirs("data/logs", exist_ok=True)
logger.add("data/logs/dns.log", rotation="25 MB", level="DEBUG", enqueue=True)

# 关闭flask的日志
getLogger("werkzeug").disabled = True


def create_app(dns):
    app = Flask(__name__)
    app.config["dns"] = dns
    app.register_blueprint(bp)
    return app


def main():
    dns = DNSServer()
    manager_t = Thread(target=dns.start)
    try:
        manager_t.start()
        app = create_app(dns)
        app.run(host="0.0.0.0", port=4348)
    except Exception:
        print("正在关闭服务器...")
        dns.running = False
        manager_t.join()


if __name__ == "__main__":
    main()
