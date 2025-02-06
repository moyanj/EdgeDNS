import socket
import concurrent.futures
from traceback import format_exc
from dns import message, rdatatype, rcode, rrset, resolver
from typing import Optional, List, Dict, Any, Tuple
import ujson
from xdb import XdbSearcher
from loguru import logger

config = ujson.load(open("data/config.json", "r"))


def lpm(s1: List[str], s2: List[str]) -> int:
    """
    计算两个列表的最长公共前缀（LPM）长度，确保层级匹配。
    """
    match_length = 0
    for i in range(min(len(s1), len(s2))):
        if s1[i] == s2[i]:
            match_length += 1
        else:
            break
    return match_length


def is_sub_line(
    records: List[Dict[str, str]], location: str
) -> Optional[Dict[str, str]]:
    """
    根据层级一致性匹配最佳线路。
    """
    location_list = location.split("/")
    top_region = location_list[0]  # 获取顶层区域（国家）

    # 过滤出与顶层区域相同的记录
    filtered_records = [
        rec for rec in records if rec["location"].split("/")[0] == top_region
    ]

    if not filtered_records:
        return None  # 如果没有匹配的国家/地区，直接返回 None

    # 计算最长公共前缀（LPM）长度
    best_match = max(
        (
            (rec, lpm(rec["location"].split("/"), location_list))
            for rec in filtered_records
        ),
        key=lambda x: x[1],  # 按匹配层级排序
        default=(None, 0),
    )

    return best_match[0] if best_match[1] > 0 else None


class DNSRecords:
    def __init__(self):
        self.records: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        content_buffer = XdbSearcher.loadContentFromFile("static/ip2region.xdb")
        self.xdb = XdbSearcher(contentBuff=content_buffer)

    def add_record(
        self,
        domain: str,
        record_type: str,
        record: str,
        ttl: int = 300,
        location: str = "default",
    ) -> None:
        if domain not in self.records:
            self.records[domain] = {}
        if record_type not in self.records[domain]:
            self.records[domain][record_type] = []
        exists = self.get_record_from_records(
            self.records[domain][record_type], location
        )
        if exists is not None:
            self.records[domain][record_type].remove(exists)
        self.records[domain][record_type].append(
            {"record": record, "location": location, "ttl": ttl}
        )

    def remove_record(self, domain: str, record_type: str) -> None:
        if domain in self.records:
            if record_type in self.records[domain]:
                del self.records[domain][record_type]
                if not self.records[domain]:
                    del self.records[domain]

    def get_records(
        self, domain: str, record_type: str, ip: str
    ) -> Optional[Dict[str, Any]]:
        if domain in self.records and record_type in self.records[domain]:
            records_list = self.records[domain][record_type]
            client_location = self.get_ip_location(ip)
            logger.info(f"来自 {client_location} 的请求")
            record = is_sub_line(records_list, client_location)
            if record is None:
                logger.info(f"未找到 {client_location} 的特定记录")
                return self.get_record_from_records(records_list, "default")
            return record
        logger.info(f"未找到 {domain} 的 {record_type} 记录")
        return self.dns_fallback(domain, record_type)

    def dns_fallback(self, domain: str, type: str):
        resolv = resolver.Resolver(configure=False)
        resolv.nameservers = config["dns_fallback"]
        try:
            # 执行 DNS 查询
            answers = resolv.resolve(domain, type)

            # 将查询结果转换为字符串
            answer_str = " ".join(
                str(answers.response.answer[0]).split(" ")[4:]
            )  # 暂时返回第一个答案的字符串表示
            ret = {"record": answer_str, "ttl": answers.response.answer[0].ttl}
            logger.info(f"Fallback查询结果：{answer_str}")
            return ret
        except Exception as e:
            logger.error(f"Fallback查询失败：{e}")
            return None

    def get_record_from_records(
        self, records: List[Dict[str, Any]], location: str
    ) -> Optional[Dict[str, Any]]:
        for record in records:
            if record["location"] == location:
                return record
        return None

    def domain_exists(self, domain: str) -> bool:
        return domain in self.records

    def get_ip_location(self, ip: str) -> str:
        return self.xdb.search(ip)

    def dump(self, file_path: str) -> None:
        """将所有记录保存到文件中，支持 JSON 和 ASCII 文件。"""
        try:
            with open(file_path, "w") as file:
                ujson.dump(self.records, file, ensure_ascii=False, indent=4)
        except Exception as e:
            logger.error(f"保存 DNS 记录时出错：{e}")

    @classmethod
    def load(cls, file_path: str) -> "DNSRecords":
        """从文件中加载记录，支持 JSON 和 ASCII 文件。"""
        try:
            with open(file_path, "r") as file:
                records = ujson.load(file)
            dns_records = cls()
            dns_records.records = records
            return dns_records
        except Exception as e:
            logger.error(f"加载 DNS 记录时出错：{e}")
            return cls()


class DNSServer:

    def __init__(
        self, ip: str = "127.0.0.1", port: int = 53, file: str = "data/records.json"
    ):
        self.server_ip: str = ip
        self.server_port: int = port
        self.file = file
        self.records = self.load_records()
        self.executor: concurrent.futures.ThreadPoolExecutor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=10)
        )
        self.running: bool = False

    def create_response(self, query: message.Message, ip: str) -> message.Message:
        """根据客户端查询构造响应。"""
        qname = query.question[0].name
        qtype = query.question[0].rdtype
        qtype_text = rdatatype.to_text(qtype)

        response = message.make_response(query)
        response.flags |= 0x0100  # 设置 Recursion Available 等标志

        domain = str(qname)
        logger.info(f"查询 {domain} 的 {qtype_text} 记录")
        rec = self.records.get_records(domain, qtype_text, ip)
        if rec is not None:
            try:
                rr = rrset.from_text(
                    domain, rec["ttl"], "IN", qtype_text, rec["record"]
                )
                response.answer.append(rr)
            except Exception as e:
                logger.error(f"构造 RRset 时出错：{e}")
                response.set_rcode(rcode.SERVFAIL)
        else:
            response.set_rcode(rcode.NOERROR)  # 没有记录，返回 NOERROR

        return response

    def handle_request(
        self, data: bytes, addr: Tuple[str, int], sock: socket.socket
    ) -> None:
        """处理收到的 DNS 查询请求。"""
        self.load_records()
        try:
            logger.info(f"收到来自 {addr[0]}:{addr[1]} 的查询请求")
            query = message.from_wire(data)
            response = self.create_response(query, addr[0])
            sock.sendto(response.to_wire(), addr)
        except Exception as e:
            print(format_exc())
            logger.error(f"处理请求时出错：{e}")

    def load_records(self) -> DNSRecords:
        """从文件中加载 DNS 记录。"""
        self.records = DNSRecords.load(self.file)
        return self.records

    def start(self) -> None:
        """启动 DNS 服务器，循环监听 UDP 请求。"""
        self.running = True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind((self.server_ip, self.server_port))
                logger.info(
                    f"DNS服务器已启动，监听地址：{self.server_ip}:{self.server_port}"
                )

                while self.running:
                    data, addr = s.recvfrom(512)
                    self.executor.submit(self.handle_request, data, addr, s)
        except Exception as e:
            logger.error(f"监听请求时出错：{e}")

    def save_records(self) -> None:
        """将 DNS 记录保存到文件中。"""
        self.records.dump(self.file)

    def get_records(self):
        return self.records.records


# 示例：添加记录并启动 DNS 服务器
if __name__ == "__main__":

    server = DNSServer(ip="127.0.0.1", port=53, file="data/records.json")
    server.start()
