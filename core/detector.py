import logging
from core.utils import *
from datetime import datetime


# UA判定型代码正则
pattern_list_ua = [
    re.compile(r'navigator\.useragent\.tolocalelowercase\(\)\.indexof.+document\.title'),
    re.compile(r'navigator\.useragent\.match\([^()]+\).+document\.title'),
    re.compile(r'navigator\.useragent\.tolocalelowercase\(\).+document\.title[^<>]', re.DOTALL),
    re.compile(r'window\.location\.tostring\(\).indexof\([^()]+\).+window\.location\.href'),
    re.compile(r'navigator\.useragent.+includes\([^()]+\).+document\.title'),
    re.compile(r'regexp.+document\.referrer.+window\.location\.href', re.DOTALL),
    re.compile(r'navigator\.useragent\.tolowercase\(\).+document\.title'),
    re.compile(r'navigator\.useragent\.match\(.+\).+viewport.+hidden.+iframe.+src.+frameborder', re.DOTALL),
    re.compile(r'i\.test\(navigator\.useragent\).+document\.referrer\.tolowercase.+referrer\.includes.+window\.location\.href', re.DOTALL),
    re.compile(r'document\.referrer.+navigator\.useragent\.tolowercase.+frameborder.+iframe.+viewport', re.DOTALL),
    re.compile(r'navigator\.useragent\.tolowercase.+navigator\.useragent\.match.+document\.referrer\.match.+urlparams\.get.+window\.location\.href', re.DOTALL),
    re.compile(r'document\.title.+navigator\.useragent\.match.+<iframe.+iframe>.+document\.createelement', re.DOTALL),
    re.compile(r'navigator\.useragent\.match.+document\.referrer.+<iframe.+iframe>', re.DOTALL),
]

# JS混淆型代码特征
pattern_list_obf = [
    re.compile(r'parseint\(.+\).+string\.fromcharcode\([^()]+\).+tostring\([^()]+\).+regexp.+(?=.*javascript)(?=.*window)(?=.*document)(?=.*write)'),
    re.compile(r'eval\(function.+parseint.+string\.fromcharcode.+tostring.+replace.+regexp.+window[^<>]+split', re.DOTALL),
    re.compile(r'var.+=\s*string\.fromcharcode\([^()]+\)\s*;\s*document\.write\([^()]+\)', re.DOTALL),
    re.compile(r'''^\s*window\s*\[\s*(['"](\\x[0-9a-f]{2})+['"])\s*\]\s*\[\s*(['"](\\x[0-9a-f]{2})+['"])\s*\]\s*\(\s*(['"](\\x[0-9a-f]{2})+['"])\s*\)''', re.DOTALL),
    re.compile(r'''window\s*\[\s*(['"](\\x[0-9a-f]{2})+['"])\s*\]\s*\[\s*(['"](\\x[0-9a-f]{2})+['"])\s*\]\s*\(\s*(['"](\\x[0-9a-f]{2})+['"])\s*\).+(android|navigator)''', re.DOTALL),
    re.compile(r'''\['sojson\.[^']+'\]''', re.DOTALL),
    re.compile(r'eval.+string\.fromcharcode.+charcodeat\([^()]+\)'),
    re.compile(r'function.+math\.random.+charat.+document.createelement.+appendchild'),
    re.compile(r'jsjiami\.com\.v7'),
    re.compile(r'eval\(.+\).+tostring\([^()]+\).+replace.+regexp.+(?=.*script)(?=.*js)(?=.*document)(?=.*write)'),
]

logger = logging.getLogger(__name__)


def detect(queue_data, config):

    sample_similarity_ratio = config.get("sample_similarity_ratio")
    save_html = config.get("save_html")
    html_save_path = config.get("html_save_path")
    sample_file_path = config.get("sample_file_path")
    file_ip_data = config.get("file_ip_data")
    ip_data_url = config.get("ip_data_url")
    file_output = config["file_output"]

    # 加载样本字典
    sample_dict = load_sample_dict(sample_file_path)
    logger.info(f'Load {sum([len(value) for value in sample_dict.values()])} samples')

    data_list = []

    # 加载IP段数据，用于判断IP是否在中国大陆境内，首次运行需要下载数据
    try:
        ip_data = load_china_mainland_data(file_ip_data, ip_data_url)
    except Exception as e:
        logger.error(f'Failed to load china mainland ip data for {e}')
        cn_ip_ranges = []
    else:
        cn_ip_ranges = parse_china_mainland_data(ip_data)
        logger.info(f'Load {len(cn_ip_ranges)} ip ranges')

    # 创建保存HTML文件的目录
    if save_html:
        now = datetime.now()
        formatted_date = now.strftime('%Y%m%d')
        html_save_path_date = os.path.join(html_save_path, formatted_date)
        if not os.path.exists(html_save_path_date):
            os.makedirs(html_save_path_date)

    headers = ['域名',
               '是否爬取成功',
               '标题',
               '网站完整域名',
               '最终URL',
               '解析的IP地址',
               'IP是否在中国大陆境内',
               '移动端UA访问时最终URL',
               '不同UA的URL域名是否一致',
               '不同UA页面文本的相似度',
               '是否符合篡改特征',
               '疑似篡改代码',
               '疑似植入的JS链接',
               '疑似植入的JS链接命中正则',
               '与样本相似的文本',
               '与样本的相似度',
               '命中的原始样本',]

    detector_num = 0

    url_blank = 'about:blank'

    logger.info("Detector process started")

    while True:
        if not queue_data.empty():
            data = queue_data.get_nowait()
            if data is None:  # 检查结束信号
                break
        else:
            time.sleep(1)
            continue

        domain = data["domain"]
        is_crawler_success = data["is_crawler_success"]
        full_domain = data["full_domain"]
        final_url = data["final_url"]
        ip_address = data["ip_address"]
        content = data["content"]
        content_mobile = data["content_mobile"]
        final_url_mobile = data["final_url_mobile"]
        js_file_list = data["js_file_list"]
        is_tampered = False
        tampering_code = []
        tampering_js_urls = []
        tampering_js_patterns = []
        max_line, max_similarity, max_sample = '', 0.0, ''

        logger.info(f'Detect website {domain}')

        # 提取页面文本信息
        title, keywords, description, body_text, js_code_list = extract_text_from_html(content)
        title_mobile, keywords_mobile, description_mobile, body_text_mobile, js_code_list_mobile = (
            extract_text_from_html(content_mobile))

        is_pattern_match_js = False
        is_pattern_match_ua = False

        # 判断是否存在JS混淆型代码
        for js_code in set(js_code_list + js_code_list_mobile):
            for pattern in pattern_list_obf:
                search_result = partial_match(pattern, js_code)
                if search_result:
                    tampering_code.append(js_code)
                    is_pattern_match_js = True
                    break

        # 判断是否存在UA判定型代码
        for js_code in set(js_code_list + js_code_list_mobile):
            for pattern in pattern_list_ua:
                search_result = partial_match(pattern, js_code)
                if search_result:
                    tampering_code.append(js_code)
                    is_pattern_match_ua = True
                    break

        # 判断是否存在被植入的JS文件，可能存在多个
        for js_url, js_content in set(js_file_list):
            for pattern in pattern_list_obf + pattern_list_ua:
                search_result = partial_match(pattern, js_content)
                if search_result:
                    tampering_js_urls.append(js_url)
                    tampering_js_patterns.append(str(pattern))
                    break

        # PC端和移动端UA打开的页面最终域名是否相同
        is_final_url_same = compare_main_domains(final_url, final_url_mobile)

        # 判断IP是否在中国大陆境内
        is_china_mainland = is_china_mainland_ip(ip_address, cn_ip_ranges) if ip_address else ''

        text_desktop = '\n'.join(filter(None, [title, keywords, description, body_text]))
        text_mobile = '\n'.join(filter(None, [title_mobile, keywords_mobile, description_mobile, body_text_mobile]))

        # 判断title, keywords, description是否与篡改样本相似，并且与body中文本的相似度较低
        title_line, title_similarity, title_sample = text_sample_similarity(
            '\n'.join(filter(None, [title, title_mobile])), sample_dict, target_similarity=1.0)
        if title_similarity > max_similarity:
            max_line, max_similarity, max_sample = title_line, title_similarity, title_sample

        is_title_abnormal = title_similarity >= sample_similarity_ratio

        meta_line, meta_similarity, meta_sample = text_sample_similarity(
            '\n'.join(filter(None, [keywords, description, keywords_mobile, description_mobile])),
            sample_dict,
            target_similarity=1.0)
        if meta_similarity > max_similarity:
            max_line, max_similarity, max_sample = meta_line, meta_similarity, meta_sample

        is_meta_abnormal = meta_similarity >= sample_similarity_ratio

        # 提取body中与样本相似的文本
        if is_title_abnormal and is_meta_abnormal:
            body_line, body_similarity, body_sample = '', 0.0, ''
        else:
            body_line, body_similarity, body_sample = text_sample_similarity(
                '\n'.join(filter(None, [body_text, body_text_mobile])),
                sample_dict,
                target_similarity=sample_similarity_ratio)
        if body_similarity > max_similarity:
            max_line, max_similarity, max_sample = body_line, body_similarity, body_sample

        is_body_abnormal = body_similarity >= sample_similarity_ratio

        # 计算主机端和移动端UA访问页面内容的相似度
        similarity_desktop_mobile = compute_similarity(text_desktop, text_mobile)

        logger.debug(f'Text of {domain} with desktop UA: {text_desktop[:500]}\n\n'
                     f'Text of {domain} with mobile UA: {text_mobile[:500]}\n\n'
                     f'Similarity: {similarity_desktop_mobile}')

        # 存在以下两种及以上情况，则判定为被篡改：
        # 1.存在JS混淆型代码
        # 2.存在UA判定型代码
        # 3.存在疑似植入的JS文件
        # 4.PC端UA和移动端UA跳转至不同的页面
        # 5.title中存在和篡改样本相似的文本
        # 6.keywords, description中存在和篡改样本相似的文本
        # 7.body中存在和篡改样本相似的文本
        # 8.命中的相似样本长度超过阈值
        if sum([1 for flag in [
            is_pattern_match_js,
            is_pattern_match_ua,
            tampering_js_urls,
            not is_final_url_same and final_url != url_blank and final_url_mobile != url_blank,
            is_title_abnormal,
            is_meta_abnormal,
            is_body_abnormal,
            max_similarity >= sample_similarity_ratio and len(max_sample) >= 10
        ] if flag]) >= 2:
            is_tampered = True

        logger.info(f'\n'
                    f'{domain} is tampered: {is_tampered}\n'
                    f'is_pattern_match_js: {is_pattern_match_js}\n'
                    f'is_pattern_match_ua: {is_pattern_match_ua}\n'
                    f'tampering_js_urls: {len(tampering_js_urls)}\n'
                    f'is_final_url_same: {is_final_url_same}\n'
                    f'is_title_abnormal: {is_title_abnormal}\n'
                    f'is_meta_abnormal: {is_meta_abnormal}\n'
                    f'is_body_abnormal: {is_body_abnormal}\n'
                    f'max_similarity: {max_similarity}\n'
                    f'max_sample_length: {len(max_sample)}')

        # 输出结果
        output_data = [domain,  # 域名
                       '是' if is_crawler_success else '否',  # 是否爬取成功
                       remove_control_characters(title),  # 标题
                       full_domain,  # 网站完整域名
                       final_url,  # 最终URL
                       ip_address,  # 解析的IP地址
                       is_china_mainland,  # IP是否在中国大陆境内
                       final_url_mobile,  # 移动端UA访问时最终URL
                       '是' if is_final_url_same else '否',  # 不同UA的URL域名是否一致
                       similarity_desktop_mobile,  # 不同UA页面文本的相似度
                       '是' if is_tampered else '否',  # 是否符合篡改特征
                       '\n\n'.join(tampering_code) if is_tampered else '',  # 疑似篡改代码
                       '\n'.join(tampering_js_urls),  # 疑似植入的JS链接
                       '\n'.join(tampering_js_patterns),  # 疑似植入的JS链接命中正则
                       max_line,  # 与样本相似的文本
                       max_similarity,  # 与样本的相似度
                       max_sample,]  # 命中的原始样本
        data_list.append(output_data)

        logger.debug(str(output_data))

        # 保存HTML文件
        if save_html and full_domain:
            if content:
                save_page_content(html_save_path_date, f'{full_domain}_desktop', content)
            if content_mobile:
                save_page_content(html_save_path_date, f'{full_domain}_mobile', content_mobile)

        detector_num += 1
        if detector_num % 1000 == 0:
            save_data_to_excel(file_output, headers, data_list)

    save_data_to_excel(file_output, headers, data_list)

    logger.info("Detector process finished")

