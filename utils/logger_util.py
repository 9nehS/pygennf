import logging
import sys

DEFAULT_LOGGER_LEVEL = logging.INFO
DEFAULT_LOG_FORMAT = '%(asctime)s[%(levelname)s][%(name)s][%(filename)s]:%(lineno)s - %(message)s'
LOGGER_LEVEL_MAP = {'info': logging.INFO, 'debug': logging.DEBUG}


def get_logger(logger_name, logger_level=DEFAULT_LOGGER_LEVEL, logger_stream=sys.stdout):
    logger = logging.getLogger(logger_name)
    logging.basicConfig(format=DEFAULT_LOG_FORMAT, stream=logger_stream)
    logger.setLevel(logger_level or DEFAULT_LOGGER_LEVEL)
    return logger


def set_logger_level(logger, logger_level='info'):
    logger.setLevel(LOGGER_LEVEL_MAP[logger_level.lower()])
