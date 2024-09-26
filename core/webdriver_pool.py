import logging
import threading
from queue import Queue
from selenium import webdriver
from selenium.webdriver.chrome.options import Options


logger = logging.getLogger(__name__)


class WebDriverPool:
    def __init__(self, config, pool_size):
        self.pool_size = pool_size
        self.config = config
        self.lock = threading.Lock()
        self.driver_usage = {}  # 记录每个driver的使用次数
        self.max_usage = config.get("webdriver_max_usage")
        self.drivers = Queue(maxsize=self.pool_size)
        self._create_drivers(self.pool_size)
        self.drivers_mobile = Queue(maxsize=self.pool_size)
        self._create_drivers_mobile(self.pool_size)

    def _create_drivers(self, num):
        # 生成UA为主机端的WebDriver实例池
        # 使用 ChromeOptions 配置，减少性能开销，并忽略证书错误
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--blink-settings=imagesEnabled=false")
        chrome_options.add_argument("start-maximized")
        chrome_options.add_argument("enable-automation")
        chrome_options.add_argument("--disable-browser-side-navigation")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")

        # 禁止自动下载文件，并设置下载目录
        chrome_options.add_experimental_option("prefs", {
            "download.prompt_for_download": False,  # 禁止下载提示
            "download.default_directory": "tmp",  # 设置下载目录
            "download.directory_upgrade": True,
            "profile.default_content_setting_values.automatic_downloads": 2  # 禁止多文件下载
        })

        # 指定user_agent，包含百度爬虫的特征，针对user_agent判定型代码
        user_agent = self.config.get("crawler_user_agent_host")
        chrome_options.add_argument(f"user-agent={user_agent}")

        # 指定chromedriver路径
        chrome_driver_path = self.config.get("chrome_driver_path")

        # 设置日志记录的首选项
        chrome_options.set_capability(
            "goog:loggingPrefs", {"performance": "ALL", "browser": "ALL"}
        )

        # 创建ChromeService实例
        chrome_service = webdriver.ChromeService(chrome_driver_path)

        # 初始化WebDriver
        for _ in range(num):
            driver = webdriver.Chrome(options=chrome_options,
                                      service=chrome_service,
                                      keep_alive=True)
            driver.set_page_load_timeout(self.config.get("max_wait_time"))
            self.drivers.put(driver)
            self.driver_usage[driver] = 0
        logging.info(f'Create {num} host webdriver')

    def _create_drivers_mobile(self, num):
        # 生成UA为移动端的WebDriver实例池
        # 使用 ChromeOptions 配置，减少性能开销，并忽略证书错误
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--blink-settings=imagesEnabled=false")
        chrome_options.add_argument("start-maximized")
        chrome_options.add_argument("enable-automation")
        chrome_options.add_argument("--disable-browser-side-navigation")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")

        # 禁止自动下载文件，并设置下载目录
        chrome_options.add_experimental_option("prefs", {
            "download.prompt_for_download": False,  # 禁止下载提示
            "download.default_directory": "tmp",  # 设置下载目录
            "download.directory_upgrade": True,
            "profile.default_content_setting_values.automatic_downloads": 2  # 禁止多文件下载
        })

        # 指定user_agent，包含百度爬虫的特征，针对user_agent判定型代码
        user_agent = self.config.get("crawler_user_agent_mobile")
        chrome_options.add_argument(f"user-agent={user_agent}")

        # 指定chromedriver路径
        chrome_driver_path = self.config.get("chrome_driver_path")

        # 创建ChromeService实例
        chrome_service = webdriver.ChromeService(chrome_driver_path)

        # 初始化WebDriver
        for _ in range(num):
            driver = webdriver.Chrome(options=chrome_options, service=chrome_service, keep_alive=True)

            # 加上ontouchend属性
            driver.execute_script("Object.defineProperty(document, 'ontouchend', {value: null, writable: true})")

            # 启动浏览器会话，并设置请求头，模拟来自百度搜索引擎的访问
            driver.execute_cdp_cmd('Network.setExtraHTTPHeaders', {'headers': {'Referer': 'https://www.baidu.com'}})

            # 启用网络功能
            driver.execute_cdp_cmd('Network.enable', {})

            driver.set_page_load_timeout(self.config.get("max_wait_time"))

            self.drivers_mobile.put(driver)
            self.driver_usage[driver] = 0
        logging.info(f'Create {num} mobile webdriver')

    def get_driver(self):
        with self.lock:
            return self.drivers.get()

    def get_driver_mobile(self):
        with self.lock:
            return self.drivers_mobile.get()

    def return_driver(self, driver, create_new_driver=False):
        self.driver_usage[driver] += 1
        if self.driver_usage[driver] >= self.max_usage:
            self.restart_driver(driver)
        elif create_new_driver:
            self.restart_driver(driver)
        else:
            with self.lock:
                self.drivers.put(driver)

    def return_driver_mobile(self, driver, create_new_driver=False):
        self.driver_usage[driver] += 1
        if self.driver_usage[driver] >= self.max_usage:
            self.restart_driver_mobile(driver)
        elif create_new_driver:
            self.restart_driver_mobile(driver)
        else:
            with self.lock:
                self.drivers_mobile.put(driver)

    def close_all(self):
        while not self.drivers.empty():
            driver = self.drivers.get()
            driver.quit()

        while not self.drivers_mobile.empty():
            driver = self.drivers_mobile.get()
            driver.quit()

    def restart_driver(self, driver):
        try:
            driver.quit()
        except Exception as e:
            logging.error(f'Close driver error for {e}')
            pass
        del self.driver_usage[driver]
        self._create_drivers(1)
        logger.info('Restart host webdriver')

    def restart_driver_mobile(self, driver):
        try:
            driver.quit()
        except Exception as e:
            logging.error(f'Close driver error for {e}')
            pass
        del self.driver_usage[driver]
        self._create_drivers_mobile(1)
        logger.info('Restart mobile webdriver')

