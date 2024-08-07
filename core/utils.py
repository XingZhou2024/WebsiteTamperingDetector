import os
import time
import jieba
import socket
import requests
import ipaddress
from collections import Counter
from openpyxl import Workbook


def download_china_mainland_data(file_path, ip_data_url):
    """下载中国大陆境内IP数据"""
    response = requests.get(ip_data_url, stream=True, timeout=(10, 3600))
    with open(file_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)


def load_china_mainland_data(file_path, ip_data_url):
    """优先从缓存文件中加载数据"""
    if not os.path.exists(file_path):
        download_china_mainland_data(file_path, ip_data_url)
    with open(file_path, 'r') as file:
        return file.read()


def parse_china_mainland_data(ip_data):
    """解析IP段数据"""
    cn_ip_ranges = []
    for line in ip_data.splitlines():
        cn_ip_ranges.append(ipaddress.ip_network(line))
    return cn_ip_ranges


def is_china_mainland_ip(ip, cn_ip_ranges):
    """判断IP是否属于中国大陆境内"""
    if not cn_ip_ranges:
        return '未知'
    ip_address = ipaddress.ip_address(ip)
    for network in cn_ip_ranges:
        if ip_address in network:
            return '是'
    return '否'


def resolve_domain(domain, max_retries=3, timeout=3):
    """解析域名的IP地址"""
    retries = 0
    while retries < max_retries:
        try:
            # 设置超时时间
            socket.setdefaulttimeout(timeout)
            ip_address = socket.gethostbyname(domain)
            return ip_address
        except (socket.timeout, socket.gaierror) as e:
            retries += 1
            time.sleep(1)  # 等待一段时间后重试
    return ''


def extract_keywords(text, max_num=20):
    """切词并选取出现最多的词语"""
    # 使用jieba分词
    words = jieba.cut(text)

    # 统计词频
    word_count = Counter(words)

    # 过滤掉单字和标点符号
    filtered_words = [(word, count) for word, count in word_count.items() if len(word) > 1]

    # 获取前top_n的关键词
    keywords = sorted(filtered_words, key=lambda x: x[1], reverse=True)[:max_num]

    return [keyword[0] for keyword in keywords]


def calculate_match_and_ratio(input_words, keyword_combinations, all_keywords, max_num=10):
    """计算匹配的关键词组合和出现的词语在所有关键词中的占比"""
    if not input_words:
        return [], 0.0

    matched_combinations = []
    input_word_set = set(input_words)
    matched_words = set()

    for combination in keyword_combinations:
        if all(word in input_word_set for word in combination):
            matched_combinations = combination
            break

    for word in input_words[:max_num]:
        if word in all_keywords:
            matched_words.add(word)

    ratio = round(len(matched_words) / len(input_words[:max_num]), 2) if input_words else 0.0

    return matched_combinations, ratio


def load_keywords(file_path):
    """加载关键词"""
    with open(file_path, 'r', encoding='utf-8') as f:
        keyword_combinations = []
        all_keywords = set()
        for line in f:
            keywords = line.strip().split('\t')
            keyword_combinations.append(keywords)
            all_keywords.update(keywords)
        return keyword_combinations, all_keywords


def filter_long_lines(content, max_length=1000):
    """过滤过长的行避免影响正则匹配的效率"""
    lines = content.splitlines()
    filtered_lines = [line for line in lines if len(line) <= max_length]
    return "\n".join(filtered_lines)


def save_data_to_excel(file_path, headers, data):
    """将数据写入Excel文件"""
    wb_save = Workbook()
    ws_save = wb_save.active
    # 写入标题
    for col_index, header in enumerate(headers, start=1):
        ws_save.cell(row=1, column=col_index, value=header)

    # 写入数据
    for row_index, row_data in enumerate(data, start=2):
        for col_index, cell_value in enumerate(row_data, start=1):
            ws_save.cell(row=row_index, column=col_index, value=cell_value)

    wb_save.save(file_path)


def calculate_similarity(list1, list2):
    """计算两个关键词列表的相似度"""
    set1, set2 = set(list1), set(list2)
    intersection = len(set1 & set2)
    union = min(len(set1), len(set2))
    similarity = round(intersection / union if union else 0, 2)
    return similarity

