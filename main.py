import yaml
import logging
import multiprocessing
from core.crawler import CrawlerPool
from core.detector import detect
from core.logger import setup_logging
from core.webdriver_pool import WebDriverPool


def main():
    # 设置日志记录
    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("Starting Website Tampering Detector...")

    # 读取配置文件
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)

    file_input = config["file_input"]
    num_crawler_processes = config["num_crawler_processes"]

    with open(file_input, 'r') as f:
        domains = [line.strip() for line in f]

    queue_data = multiprocessing.Queue()

    # 启动判定进程
    check_process = multiprocessing.Process(target=detect, args=(queue_data, config))
    check_process.start()

    # 创建WebDriver实例池
    webdriver_pool = WebDriverPool(config)

    # 启动爬取线程池
    crawler_pool = CrawlerPool(num_crawler_processes, config, webdriver_pool)
    crawler_pool.crawler(domains, queue_data)

    # 结束判定进程
    queue_data.put(None)
    check_process.join()

    logger.info("Website Tampering Detector finished.")


if __name__ == "__main__":
    main()
