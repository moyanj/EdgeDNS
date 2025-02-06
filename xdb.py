import socket
import struct
import io
import sys
import ujson


# xdb默认参数
HeaderInfoLength = 256
VectorIndexRows = 256
VectorIndexCols = 256
VectorIndexSize = 8
SegmentIndexSize = 14


class XdbSearcher(object):
    __f = None

    # the minimal memory allocation.
    vectorIndex = None
    # 整个读取xdb，保存在内存中
    contentBuff = None

    @staticmethod
    def loadContentFromFile(dbfile):
        try:
            with io.open(dbfile, "rb") as f:
                return f.read()
        except IOError as e:
            print(f"[Error]: {e}")
            return None

    def __init__(self, dbfile=None, vectorIndex=None, contentBuff=None):
        self.init_database(dbfile, vectorIndex, contentBuff)
        self.countries = ujson.load(open("static/countries.json", "r"))

    def search(self, ip):
        """根据IP地址查询对应区域信息"""
        if not isinstance(ip, int):
            ip = self.ip2long(ip)
        return self.search_by_ip_long(ip)

    def search_by_ip_long(self, ip):
        """根据IP地址的Long值查询区域信息"""
        # 定位到段索引块
        s_ptr, e_ptr = self.get_content_index(ip)
        if s_ptr == e_ptr == 0:
            return ""

        # 二分查找段索引块以获取区域信息
        data_len, data_ptr = self.binary_search_segment_index(s_ptr, e_ptr, ip)
        if data_ptr < 0:
            return ""

        # 读取区域信息
        buffer_string = self.read_buffer(data_ptr, data_len)
        if buffer_string:
            return self.convert_format(buffer_string.decode("utf-8"))
        return ""

    def get_content_index(self, ip):
        """根据IP地址定位到段索引块"""
        il0 = (ip >> 24) & 0xFF
        il1 = (ip >> 16) & 0xFF
        idx = il0 * VectorIndexCols * VectorIndexSize + il1 * VectorIndexSize

        s_ptr = e_ptr = 0
        if self.vectorIndex is not None:
            s_ptr = self.get_long(self.vectorIndex, idx)
            e_ptr = self.get_long(self.vectorIndex, idx + 4)
        elif self.contentBuff is not None:
            base_offset = HeaderInfoLength + idx
            s_ptr = self.get_long(self.contentBuff, base_offset)
            e_ptr = self.get_long(self.contentBuff, base_offset + 4)
        else:
            try:
                self.__f.seek(HeaderInfoLength + idx)  # type: ignore[attr-defined]
                buffer_ptr = self.__f.read(8)  # type: ignore[attr-defined]
                s_ptr = self.get_long(buffer_ptr, 0)
                e_ptr = self.get_long(buffer_ptr, 4)
            except IOError as e:
                print(f"[Error]: {e}")
        return s_ptr, e_ptr

    def binary_search_segment_index(self, s_ptr, e_ptr, ip):
        """在段索引块中进行二分查找"""
        data_len = data_ptr = -1
        low = 0
        high = (e_ptr - s_ptr) // SegmentIndexSize

        while low <= high:
            mid = (low + high) // 2
            offset = s_ptr + mid * SegmentIndexSize
            buffer_sip = self.read_buffer(offset, SegmentIndexSize)
            if not buffer_sip:
                break

            sip = self.get_long(buffer_sip, 0)
            if ip < sip:
                high = mid - 1
            else:
                eip = self.get_long(buffer_sip, 4)
                if ip > eip:
                    low = mid + 1
                else:
                    data_len = self.read_short(buffer_sip, 8)
                    data_ptr = self.get_long(buffer_sip, 10)
                    break
        return data_len, data_ptr

    def read_buffer(self, offset, length):
        """从缓存或文件中读取数据"""
        if self.contentBuff is not None:
            return self.contentBuff[offset : offset + length]
        try:
            if self.__f and self.__f.seek(offset):
                return self.__f.read(length)
        except IOError as e:
            print(f"[Error]: {e}")
        return b""

    def init_database(self, dbfile, vi, cb):
        """初始化数据库"""
        try:
            if cb is not None:
                self.__f = None
                self.vectorIndex = None
                self.contentBuff = cb
            else:
                self.__f = io.open(dbfile, "rb")
                self.vectorIndex = vi
        except IOError as e:
            print(f"[Error]: {e}")
            sys.exit()

    @staticmethod
    def ip2long(ip):
        """将IP地址转换为Long值"""
        _ip = socket.inet_aton(ip)
        return struct.unpack("!L", _ip)[0]

    @staticmethod
    def get_long(buffer, offset):
        """从缓冲区中读取4字节Long值"""
        if len(buffer[offset : offset + 4]) == 4:
            return struct.unpack("I", buffer[offset : offset + 4])[0]
        return 0

    @staticmethod
    def read_short(buffer, offset):
        """从缓冲区中读取2字节Short值"""
        return (buffer[offset] & 0x00FF) | (buffer[offset + 1] << 8)

    def close(self):
        """关闭文件句柄并释放资源"""
        if self.__f is not None:
            self.__f.close()
        self.vectorIndex = None
        self.contentBuff = None

    def convert_format(self, input_string):
        # 将输入字符串按 "|" 分割，并忽略所有的 "0" 和最后一个元素
        parts = input_string.split("|")
        parts = parts[:-1]
        filtered_parts = [part for part in parts if part != "0" and part.strip() != ""]
        country = filtered_parts[0]
        country_parts = self.countries.get(
            country,
            country + "/",
        )
        filtered_parts = [country_parts.split("/")[0]] + filtered_parts
        # 用 "/" 连接剩下的部分并返回
        return "/".join(filtered_parts)


if __name__ == "__main__":
    ip_array = ["170.64.183.169", "36.143.122.11"]
    db_path = "static/ip2region.xdb"

    # 加载整个内容到内存
    content_buffer = XdbSearcher.loadContentFromFile(db_path)
    if content_buffer is None:
        print("Failed to load content from file.")
        sys.exit()

    # 创建查询对象
    searcher = XdbSearcher(contentBuff=content_buffer)

    # 执行查询
    for ip in ip_array:
        region_str = searcher.search(ip)
        print(region_str)

    # 释放资源
    searcher.close()
