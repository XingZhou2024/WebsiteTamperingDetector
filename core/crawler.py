import socket
import threading
import logging
from concurrent.futures import ThreadPoolExecutor
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
from core.utils import *


logger = logging.getLogger(__name__)


class Crawler:
    def __init__(self, config, webdriver_pool):
        self.max_wait_time = config.get("max_wait_time")
        self.num_crawler_processes = config.get("num_crawler_processes")
        self.config = config
        self.webdriver_pool = webdriver_pool

    def crawler(self, domain):
        logger.info(f'Start crawler {domain}')
        driver = self.webdriver_pool.get_driver()
        try:
            full_domain = domain
            ip_address = resolve_domain(full_domain)
            if not ip_address:
                full_domain = f'www.{domain}'
                ip_address = resolve_domain(full_domain)

            if not ip_address:
                logger.error(f'{domain} crawler failed for IP resolution.')
                # 返回爬取失败结果
                data = {
                    "domain": domain,
                    "is_crawler_success": False,
                    "full_domain": '',
                    "final_url": '',
                    "ip_address": '',
                    "content": ''
                }

                return data

            driver.get(f'http://{full_domain}')

            # 等待页面加载完成
            WebDriverWait(driver, self.max_wait_time).until(
                expected_conditions.presence_of_element_located((By.TAG_NAME, 'body'))
            )

            # 爬取页面内容
            content = driver.page_source
            final_url = driver.current_url

            # 生成数据结构
            data = {
                "domain": domain,
                "is_crawler_success": True,
                "full_domain": full_domain,
                "final_url": final_url,
                "ip_address": ip_address,
                "content": content
            }

            return data

        except UnexpectedAlertPresentException:
            try:
                alert = driver.switch_to.alert
                alert_text = alert.text
                logger.info(f"Alert text：{alert_text}")
                alert.accept()  # 关闭弹窗

            except NoAlertPresentException:
                pass  # 如果没有弹窗，继续执行

        except Exception as e:
            logger.error(f"{domain} crawler failed for {e}")

            # 返回爬取失败结果
            data = {
                "domain": domain,
                "is_crawler_success": False,
                "full_domain": '',
                "final_url": '',
                "ip_address": '',
                "content": ''
            }

            return data
        finally:
            self.webdriver_pool.return_driver(driver)


class CrawlerPool:
    def __init__(self, num_crawler_processes, config, webdriver_pool):
        self.num_crawler_processes = num_crawler_processes
        self.config = config
        self.webdriver_pool = webdriver_pool
        self.crawlers = [Crawler(config, webdriver_pool) for _ in range(num_crawler_processes)]
        self.lock = threading.Lock()
        self.next_crawler = 0
        logger.info("CrawlerPool initialized")

    def _get_next_crawler(self):
        with self.lock:
            crawler = self.crawlers[self.next_crawler]
            self.next_crawler = (self.next_crawler + 1) % self.num_crawler_processes
        return crawler

    def crawler(self, domains, queue_data):
        with ThreadPoolExecutor(max_workers=self.num_crawler_processes) as executor:
            futures = [executor.submit(self._crawler_and_queue, domain, queue_data) for domain in domains]
            for future in futures:
                future.result()
        logger.info("All crawler tasks completed")

    def _crawler_and_queue(self, domain, queue_data):
        crawler = self._get_next_crawler()
        data = crawler.crawler(domain)
        if data:
            queue_data.put(data)

    def close(self):
        self.webdriver_pool.close_all()
        logger.info("CrawlerPool closed")

