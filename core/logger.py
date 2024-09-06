import os
import yaml
import logging
import logging.handlers


def setup_logging(config_path):
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    log_file = config.get("log_file")

    log_root = os.path.split(log_file)[0]
    if not os.path.exists(log_root):
        os.makedirs(log_root)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # 创建文件处理器
    file_handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=10485760, backupCount=3)
    file_handler.setLevel(logging.INFO)

    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)

    # 创建格式化器并将其添加到处理器
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # 将处理器添加到日志记录器
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

