import json
import logging
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
from selenium.common.exceptions import TimeoutException, InvalidSessionIdException
from core.utils import *


logger = logging.getLogger(__name__)


class Crawler:
    def __init__(self, config, webdriver_pool):
        self.body_wait_time = config.get("body_wait_time")
        self.num_crawler_processes = config.get("num_crawler_processes")
        self.config = config
        self.webdriver_pool = webdriver_pool

    def crawl(self, domain):
        logger.info(f'Start crawl {domain}')

        # 爬虫结果数据
        data = {
            "domain": domain,  # 原始域名
            "is_crawler_success": False,  # 是否爬取成功
            "full_domain": '',  # 访问网站时的完整域名
            "final_url": '',  # 访问网站时最终跳转的URL
            "ip_address": '',  # 网站域名的IP地址
            "content": '',  # 网站首页内容
            "content_mobile": '',  # 以移动端UA打开网站首页的内容
            "final_url_mobile": '',  # 以移动端UA打开网站时最终的URL
            "js_file_list": []  # 访问网站首页时的JS加载列表
        }

        driver = self.webdriver_pool.get_driver()
        driver_mobile = self.webdriver_pool.get_driver_mobile()

        create_new_driver = False

        try:
            full_domain = domain
            ip_address = resolve_domain(full_domain)
            if not ip_address:
                full_domain = f'www.{domain}'
                ip_address = resolve_domain(full_domain)

            if not ip_address:
                logger.error(f'{domain} crawler failed for IP resolution.')
                # 返回爬取失败结果
                return data

            try:
                # 以PC端的UA爬取页面
                driver.get(f'http://{full_domain}')
            #  处理出现弹窗的情况
            except UnexpectedAlertPresentException:
                try:
                    alert = driver_mobile.switch_to.alert
                    alert_text = alert.text
                    logger.info(f"Alert text：{alert_text}")
                    alert.accept()  # 关闭弹窗

                except NoAlertPresentException:
                    pass  # 如果没有弹窗，继续执行
            except TimeoutException:
                pass

            # 等待页面加载完成
            WebDriverWait(driver, self.body_wait_time).until(
                expected_conditions.presence_of_element_located((By.TAG_NAME, 'body'))
            )

            # 获取页面性能数据
            performance_timing = driver.execute_script("return window.performance.timing")

            # 计算页面加载时间
            navigation_start = performance_timing['navigationStart']
            load_event_end = performance_timing['loadEventEnd']

            load_time_ms = load_event_end - navigation_start
            load_time_sec = load_time_ms / 1000

            logger.info(f'Crawl {domain} with host UA, load time {load_time_sec:.2f}')

            # 获取 JavaScript 文件内容
            logs = driver.get_log('performance')
            for log in logs:
                log_entry = json.loads(log['message'])
                message = log_entry['message']
                if message['method'] == 'Network.requestWillBeSent':
                    request_url = message['params']['request']['url']
                    if not request_url.endswith('.js'):
                        continue
                    request_id = message['params']['requestId']
                    try:
                        response_body = driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                        logger.debug(f"{domain} {request_url} {response_body['body'][:500]}")
                        data["js_file_list"].append((request_url, response_body['body']))
                    except:
                        pass

            # 爬取页面内容
            content = driver.page_source
            final_url = driver.current_url

            try:
                # 以移动端的UA爬取页面
                driver_mobile.get(f'http://{full_domain}')
            #  处理出现弹窗的情况
            except UnexpectedAlertPresentException:
                try:
                    alert = driver_mobile.switch_to.alert
                    alert_text = alert.text
                    logger.info(f"Alert text：{alert_text}")
                    alert.accept()  # 关闭弹窗

                except NoAlertPresentException:
                    pass  # 如果没有弹窗，继续执行
            except TimeoutException:
                pass

            # 等待页面加载完成
            WebDriverWait(driver_mobile, self.body_wait_time).until(
                expected_conditions.presence_of_element_located((By.TAG_NAME, 'body'))
            )

            # 获取页面性能数据
            performance_timing = driver_mobile.execute_script("return window.performance.timing")

            # 计算页面加载时间
            navigation_start = performance_timing['navigationStart']
            load_event_end = performance_timing['loadEventEnd']

            load_time_ms = load_event_end - navigation_start
            load_time_sec = load_time_ms / 1000

            logger.info(f'Crawl {domain} with mobile UA, load time {load_time_sec:.2f}')

            # 爬取页面内容
            content_mobile = driver_mobile.page_source
            final_url_mobile = driver_mobile.current_url

            if content or content_mobile:
                # 生成数据结构
                data["is_crawler_success"] = True
                data["full_domain"] = full_domain
                data["final_url"] = final_url
                data["ip_address"] = ip_address
                data["content"] = content
                data["content_mobile"] = content_mobile
                data["final_url_mobile"] = final_url_mobile

            return data

        except InvalidSessionIdException as e:
            # 若出现此类错误则重新创建一个webdriver实例
            create_new_driver = True
            logger.info(f'Restart webdriver for {e}')

            return data

        except Exception as e:
            logger.error(f"{domain} crawler failed for {e}")

            return data
        finally:
            self.webdriver_pool.return_driver(driver, create_new_driver)
            self.webdriver_pool.return_driver_mobile(driver_mobile, create_new_driver)


class CrawlerPool:
    def __init__(self, num_crawler_processes, config, webdriver_pool):
        self.num_crawler_processes = num_crawler_processes
        self.config = config
        self.thread_waite_time = config.get("max_wait_time") * 2
        self.webdriver_pool = webdriver_pool
        self.crawlers = Queue(maxsize=num_crawler_processes)
        # 将所有crawler放入队列
        for _ in range(num_crawler_processes):
            self.crawlers.put(Crawler(config, webdriver_pool))

        logger.info("CrawlerPool initialized")

    def _get_crawler(self):
        return self.crawlers.get()

    def _return_crawler(self, crawler):
        self.crawlers.put(crawler)

    def crawler(self, domains, queue_data):
        with ThreadPoolExecutor(max_workers=self.num_crawler_processes) as executor:
            futures = [executor.submit(self._crawl_and_queue, domain, queue_data) for domain in domains]
            for future in futures:
                try:
                    # 设置超时，以避免某些任务无限阻塞
                    future.result(timeout=self.thread_waite_time)
                except TimeoutError:
                    logger.error("Crawling timed out")
                except Exception as e:
                    logger.error(f"Error during crawling: {str(e)}")
        logger.info("All crawler tasks completed")

    def _crawl_and_queue(self, domain, queue_data):
        crawler = self._get_crawler()
        try:
            data = crawler.crawl(domain)
            logger.info(f'Complete crawl {domain}')
            if data:
                queue_data.put_nowait(data)
                logger.info(f'Put crawl data of {domain}')
        except Exception as e:
            logger.error(f"Error in domain {domain}: {str(e)}")
        finally:
            self._return_crawler(crawler)

    def close(self):
        self.webdriver_pool.close_all()
        logger.info("CrawlerPool closed")

