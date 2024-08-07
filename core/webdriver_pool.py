import threading
from queue import Queue
from selenium import webdriver
from selenium.webdriver.chrome.options import Options


class WebDriverPool:
    def __init__(self, config):
        self.pool_size = config.get("num_crawler_processes")
        self.config = config
        self.lock = threading.Lock()
        self.drivers = Queue(maxsize=self.pool_size)
        self._create_drivers()

    def _create_drivers(self):
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

        # 指定user_agent，包含百度爬虫的特征，针对user_agent判定型代码
        user_agent = self.config.get("crawler_user_agent")
        chrome_options.add_argument(f"user-agent={user_agent}")

        # 指定chromedriver路径
        chrome_driver_path = self.config.get("chrome_driver_path")

        # 创建ChromeService实例
        chrome_service = webdriver.ChromeService(chrome_driver_path)

        # 初始化WebDriver
        for _ in range(self.pool_size):
            driver = webdriver.Chrome(options=chrome_options, service=chrome_service, keep_alive=True)
            self.drivers.put(driver)

    def get_driver(self):
        with self.lock:
            return self.drivers.get()

    def return_driver(self, driver):
        with self.lock:
            self.drivers.put(driver)

    def close_all(self):
        while not self.drivers.empty():
            driver = self.drivers.get()
            driver.quit()
