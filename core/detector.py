import logging
from bs4 import BeautifulSoup
from core.utils import *


# # UA判定型代码正则
# pattern_list_ua = [
#     re.compile(r'<script[^>]*>[^<>]+navigator\.useragent\.tolocalelowercase\(\)\.indexof.+document\.title[^<>]+</script>'),
#     re.compile(r'<script[^>]*>[^<>]+navigator\.useragent\.match\([^()]+\).+document\.title[^<>]+</script>'),
#     re.compile(r'<script[^>]*>[^<>]+navigator\.useragent\.tolocalelowercase\(\).+document\.title[^<>]+</script>', re.DOTALL),
#     re.compile(r'<script[^>]*>[^<>]+window\.location\.tostring\(\).indexof\([^()]+\).+window\.location\.href[^<>]+</script>'),
#     re.compile(r'<script[^>]*>[^<>]+navigator\.useragent.+includes\([^()]+\).+document\.title[^<>]+</script>'),
#     re.compile(r'<script[^>]*>[^<>]+regexp.+document\.referrer.+window\.location\.href[^<>]+</script>', re.DOTALL),
#     re.compile(r'<script[^>]*>[^<>]+navigator\.useragent\.tolowercase\(\).+document\.title[^<>]+</script>'),
# ]

# # JS混淆型代码特征
# pattern_list_obf = [
#     re.compile(r'<script[^>]*>.*parseint\(.+\).+string\.fromcharcode\([^()]+\).+tostring\([^()]+\).+regexp.+(?=.*javascript)(?=.*window)(?=.*document)(?=.*write).*</script>'),
#     re.compile(r'<script[^>]*>\s*eval\(function.+parseint.+string\.fromcharcode.+tostring.+replace.+regexp.+window[^<>]+split[^<>]+</script>', re.DOTALL),
#     re.compile(r'<script[^>]*>\s*var.+=\s*string\.fromcharcode\([^()]+\)\s*;\s*document\.write\([^()]+\)[^<>]+</script>', re.DOTALL),
#     re.compile(r'''<script[^>]*>[^<>]*window\s*\[\s*(['"](\\x[0-9a-f]{2})+['"])\s*\]\s*\[\s*(['"](\\x[0-9a-f]{2})+['"])\s*\]\s*\(\s*(['"](\\x[0-9a-f]{2})+['"])\s*\)[^<>]*</script>''', re.DOTALL),
#     re.compile(r'''<script[^>]*>\s*\['sojson\.[^']+'\].*</script>''', re.DOTALL),
#     re.compile(r'<script[^>]*>\s*eval.+string\.fromcharcode.+charcodeat\([^()]+\).+</script>'),
#     re.compile(r'<script[^>]*>[^<>]+function.+math\.random.+charat.+document.createelement.+appendchild[^<>]+</script>'),
#     re.compile(r'<script[^>]*>[^<>]+var.+jsjiami\.com.+</script>'),
#     re.compile(r'<script[^>]*>.*eval\(.+\).+tostring\([^()]+\).+replace.+regexp.+(?=.*script)(?=.*js)(?=.*document)(?=.*write).*</script>'),
# ]

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

    keywords_file = config.get("keywords_file_file")
    keywords_match_ratio_auxiliary = config.get("keywords_match_ratio_auxiliary")
    keywords_match_ratio_independent = config.get("keywords_match_ratio_independent")
    keywords_similarity_independent = config.get("keywords_similarity_independent")
    file_ip_data = config.get("file_ip_data")
    ip_data_url = config.get("ip_data_url")
    file_output = config["file_output"]

    keyword_combinations, all_keywords = load_keywords(keywords_file)
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

    headers = ['域名',
               '是否爬取成功',
               '标题',
               '网站域名',
               '最终URL',
               '解析的IP地址',
               'IP是否在中国大陆境内',
               '是否符合篡改特征',
               '疑似篡改代码',
               '异常文本关键词',
               '命中关键词',
               '关键词匹配度',
               '关键词与其他文本的相似度',
               '移动端UA最终URL',
               '不同UA的URL域名是否一致',
               '不同UA页面文本的相似度',
               '疑似植入的JS链接',
               '疑似植入的JS链接命中正则']

    detector_num = 0

    logger.info("Detector process started")

    while True:
        if not queue_data.empty():
            data = queue_data.get()
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
        tampering_keywords = []
        matched_combinations = []
        match_ratio = 0.0
        tampering_code = []
        keywords_similarity = 0.0
        tampering_js_urls = []
        tampering_js_patterns = []

        logger.info(f'Detect website {domain}')

        js_code_list, title, text_list_meta, text_list_body, other_text = extract_text(content)

        is_pattern_match_js = False
        is_pattern_match_ua = False
        is_text_match_meta = False
        is_text_match_body = False

        # html_content = filter_long_lines(content, 10000).lower()

        # 判断是否存在JS混淆型代码
        for js_code in js_code_list:
            for pattern in pattern_list_obf:
                search_result = partial_match(pattern, js_code)
                if search_result:
                    tampering_code.append(js_code)
                    is_pattern_match_js = True
                    break

        # 判断是否存在UA判定型代码
        for js_code in js_code_list:
            for pattern in pattern_list_ua:
                search_result = partial_match(pattern, js_code)
                if search_result:
                    tampering_code.append(js_code)
                    is_pattern_match_ua = True
                    break

        # 判断是否存在被植入的JS文件，可能存在多个
        for js_url, js_content in js_file_list:
            for pattern in pattern_list_obf + pattern_list_ua:
                search_result = partial_match(pattern, js_content)
                if search_result:
                    tampering_js_urls.append(js_url)
                    tampering_js_patterns.append(str(pattern))
                    break

        # 计算匹配的关键词组合和出现的词语在所有关键词中的占比
        text_tmp = ' '.join(text_list_meta)
        keywords_tmp = extract_keywords(text_tmp) if text_tmp else []
        matched_combinations_tmp, match_ratio_tmp = calculate_match_and_ratio(keywords_tmp,
                                                                              keyword_combinations,
                                                                              all_keywords)
        if (matched_combinations_tmp and match_ratio_tmp >= keywords_match_ratio_auxiliary
                and match_ratio_tmp > match_ratio):
            is_text_match_meta = True
            tampering_keywords = keywords_tmp
            matched_combinations = matched_combinations_tmp
            match_ratio = match_ratio_tmp

        for text_tmp in text_list_body:
            # 计算匹配的关键词组合和出现的词语在所有关键词中的占比，取符合条件且占比最高的文本内容
            keywords_tmp = extract_keywords(text_tmp) if text_tmp else []
            matched_combinations_tmp, match_ratio_tmp = calculate_match_and_ratio(keywords_tmp,
                                                                                  keyword_combinations,
                                                                                  all_keywords)
            # 若body中存在符合条件的文本，且未命中UA判定正则，则优先取body中的文本内容，除非meta中的关键词匹配度已达到独立判定阈值
            if (matched_combinations_tmp and match_ratio_tmp >= keywords_match_ratio_auxiliary
                    and (match_ratio_tmp > match_ratio
                         or (not is_pattern_match_ua and match_ratio < keywords_match_ratio_independent))):
                is_text_match_body = True
                tampering_keywords = keywords_tmp
                matched_combinations = matched_combinations_tmp
                match_ratio = match_ratio_tmp

        # 计算疑似篡改文本与网页其他文本之间的相似度
        if tampering_keywords:
            keywords_other = extract_keywords(other_text)
            keywords_similarity = calculate_similarity(tampering_keywords, keywords_other)

        is_final_url_same = compare_main_domains(final_url, final_url_mobile)

        # 判断存在网站篡改的条件：
        # 1.存在JS混淆型代码
        # 2.存在UA判定型代码且meta信息符合关键词匹配条件
        # 3.body中特定HTML结构文本符合关键词匹配条件
        # 4.关键词匹配率达到独立判定阈值且与其他文本的相似度低于阈值
        # 5.存在疑似植入的JS且PC端UA和移动端UA跳转至不同的页面
        if (is_pattern_match_js
                or (is_pattern_match_ua and is_text_match_meta)
                or is_text_match_body
                or (match_ratio >= keywords_match_ratio_independent
                    and keywords_similarity <= keywords_similarity_independent)
                or (tampering_js_urls and not is_final_url_same)):
            is_tampered = True

        # 判断IP是否在中国大陆境内
        is_china_mainland = is_china_mainland_ip(ip_address, cn_ip_ranges) if ip_address else ''

        # 计算主机端和移动端UA访问页面内容的相似度
        text_host = extract_text_from_html(content)
        text_mobile = extract_text_from_html(content_mobile)
        similarity_host_mobile = compute_similarity(text_host, text_mobile)

        logger.debug(f'Text of {domain} with host UA: {text_host[:500]}\n\n'
                    f'Text of {domain} with mobile UA: {text_mobile[:500]}\n\n'
                    f'Similarity: {similarity_host_mobile}')

        # 输出结果
        output_data = [domain,
                       '是' if is_crawler_success else '否',
                       remove_control_characters(title),
                       full_domain,
                       final_url,
                       ip_address,
                       is_china_mainland,
                       '是' if is_tampered else '否',
                       '\n\n'.join(tampering_code) if is_tampered else '',
                       ' '.join(remove_control_characters(tampering_keywords)),
                       ' '.join(matched_combinations),
                       match_ratio,
                       keywords_similarity,
                       final_url_mobile,
                       '是' if is_final_url_same else '否',
                       similarity_host_mobile,
                       '\n'.join(tampering_js_urls),
                       '\n'.join(tampering_js_patterns),]
        data_list.append(output_data)

        logger.debug(str(output_data))

        detector_num += 1
        if detector_num % 1000 == 0:
            save_data_to_excel(file_output, headers, data_list)

    save_data_to_excel(file_output, headers, data_list)

    logger.info("Detector process finished")


def extract_text(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')

    # 提取title
    title_tags = soup.find_all('title')
    title = ' '.join([title_tag.get_text(separator=' ', strip=True) for title_tag in title_tags]).strip()

    # 提取keywords
    keywords_tag = soup.find('meta', attrs={'name': 'keywords'})
    keywords = keywords_tag['content'].strip() if keywords_tag and 'content' in keywords_tag.attrs else ''

    # 提取description
    description_tag = soup.find('meta', attrs={'name': 'description'})
    description = description_tag['content'].strip() if description_tag and 'content' in description_tag.attrs else ''

    # 提取隐藏的div内容
    hidden_div_li = [div for div in soup.find_all('div', style='display:none;')
                     if len(div.attrs) == 1 and len(list(div.children)) > 1
                     and all(child.name == 'li' and len(child.attrs) <= 1 for child in div.children)]
    hidden_div_li_text = ' '.join([div.get_text(separator=' ', strip=True) for div in hidden_div_li]).strip()

    # 提取隐藏的div内容
    hidden_div_a = [div for div in soup.find_all('div', style='display:none;')
                    if len(div.attrs) == 1 and len(list(div.children)) > 1
                    and all(child.name == 'a' and len(child.attrs) <= 1 for child in div.children)]
    hidden_div_a.extend([div for div in soup.find_all('div', style='display:none;')
                         if not list(div.children)])
    hidden_div_a_text = ' '.join([div.get_text(separator=' ', strip=True) for div in hidden_div_a]).strip()

    # 提取隐藏的table内容
    hidden_tables = [table for table in
                     soup.find_all('table', {'style': 'display: none;', 'cellspacing': '0', 'cellpadding': '0'})
                     if all(child.name == 'caption' for child in table.children)]
    hidden_tables_text = ' '.join([table.get_text(separator=' ', strip=True) for table in hidden_tables]).strip()
    hidden_tables = [table for table in
                     soup.find_all('table', {'border': '0', 'cellpadding': '0', 'cellspacing': '0'})
                     if all(child.name == 'a' and len(child.attrs) <= 2 for child in table.children)]
    hidden_tables_text = hidden_tables_text + ' ' + ' '.join([table.get_text(separator=' ', strip=True)
                                                              for table in hidden_tables]).strip()

    # 提取隐藏的table内容
    hidden_div_links = [div for div in soup.find_all('div', {'style': 'font-weight:bold;'})
                        if len(list(div.children)) > 1
                        and all(child.name == 'li' and len(child.attrs) <= 1 for child in div.children)]
    hidden_div_links_text = ' '.join([div.get_text(separator=' ', strip=True) for div in hidden_div_links]).strip()

    # 剔除已提取的部分
    for tag in ([keywords_tag, description_tag]
                + title_tags + hidden_div_li + hidden_div_a + hidden_tables + hidden_div_links):
        if tag:
            tag.extract()

    # 提取剩余的文本内容
    other_text = soup.get_text(separator=' ').strip()

    text_list_meta = [keywords, description]

    text_list_body = [hidden_div_li_text, hidden_div_a_text, hidden_tables_text, hidden_div_links_text]

    # 提取所有的JS代码
    js_code_list = []

    # 查找所有的<script>标签
    for script in soup.find_all('script'):
        # 检查<script>标签是否有src属性
        if not script.has_attr('src'):
            # 提取<script>标签中的JavaScript代码
            if script.string:
                js_code_list.append(script.string.strip().lower())

    return js_code_list, title, text_list_meta, text_list_body, other_text

