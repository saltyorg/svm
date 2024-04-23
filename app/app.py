import os
import logging
import httpx
import redis.asyncio as redis
import json
from quart import Quart, request, jsonify
from uvicorn.config import LOGGING_CONFIG

# Development Configurations
DEV_CONFIG = {
    'GITHUB_PATS': 'YOUR_DEV_PAT1,YOUR_DEV_PAT2',
    'API_USAGE_THRESHOLD': 50,
    'REDIS_HOST': 'localhost'
}

is_development = os.environ.get('QUART_ENV') == 'development'
TIME_FORMAT = '%d/%m/%Y %H:%M:%S'


class LogColors:
    DEBUG = '\033[92m'    # GREEN
    INFO = '\033[94m'     # BLUE
    WARNING = '\033[93m'  # YELLOW
    ERROR = '\033[91m'    # RED
    CRITICAL = '\033[91m'  # RED
    ENDCOLOR = '\033[0m'  # Reset to the default color


class ColoredFormatter(logging.Formatter):
    def format(self, record):
        log_colors = {
            'DBG': LogColors.DEBUG,
            'INF': LogColors.INFO,
            'WRN': LogColors.WARNING,
            'ERR': LogColors.ERROR,
            'CRT': LogColors.CRITICAL,
        }
        log_level_name = record.levelname
        log_color = log_colors.get(log_level_name, LogColors.ENDCOLOR)

        record.levelname = f"{log_color}{log_level_name}{LogColors.ENDCOLOR}"

        return super(ColoredFormatter, self).format(record)


# Set configurations
if is_development:
    ACCESS_TOKENS = DEV_CONFIG['GITHUB_PATS'].split(',')
    API_USAGE_THRESHOLD = DEV_CONFIG['API_USAGE_THRESHOLD']
    REDIS_HOST = DEV_CONFIG['REDIS_HOST']
else:
    for var in ['GITHUB_PATS', 'API_USAGE_THRESHOLD', 'REDIS_HOST']:
        if not os.environ.get(var):
            raise EnvironmentError(f"{var} not set in environment variables!")
    ACCESS_TOKENS = os.environ['GITHUB_PATS'].split(',')
    API_USAGE_THRESHOLD = int(os.environ['API_USAGE_THRESHOLD'])
    REDIS_HOST = os.environ['REDIS_HOST']

# Setup logging
log_format = "%(levelname)s %(asctime)s %(message)s"
formatter = ColoredFormatter(log_format, datefmt=TIME_FORMAT)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)

# Modify log level names
logging.addLevelName(logging.CRITICAL, "CRT")
logging.addLevelName(logging.DEBUG, "DBG")
logging.addLevelName(logging.ERROR, "ERR")
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, "WRN")

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

logging.basicConfig(level=logging.INFO, handlers=[console_handler])

logging.getLogger('uvicorn').handlers = [console_handler]
logging.getLogger('uvicorn.access').handlers = [console_handler]

app = Quart(__name__)
current_token_idx = 0


redis_client = redis.StrictRedis(
    host=REDIS_HOST, port=6379, db=0, decode_responses=True)


async def get_from_cache(key):
    res = redis_client.hgetall(key)
    if isinstance(res, dict):
        return res
    return await res


async def set_to_cache(key, data, etag):
    future = redis_client.hset(
        key, mapping={"data": json.dumps(data), "etag": etag})
    assert not isinstance(future, int)
    await redis_client.expire(key, 86400)  # cache for 24 hours
    return await future


@app.route('/version', methods=["GET"])
async def proxy():
    global current_token_idx

    try:
        url_to_fetch = request.args.get('url')
        if not url_to_fetch:
            raise ValueError("url parameter is required")

        cached_resp = await get_from_cache(url_to_fetch)

        token = ACCESS_TOKENS[current_token_idx]
        current_token_idx = (current_token_idx + 1) % len(ACCESS_TOKENS)

        headers = {'Authorization': f'token {token}'}

        if cached_resp and "etag" in cached_resp:
            headers['If-None-Match'] = cached_resp["etag"]

        async with httpx.AsyncClient() as client:
            response = await client.get(url_to_fetch, headers=headers)

        remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        log_msg = (
            f"Request processed duration={response.elapsed.total_seconds():.6f}s "
            f"ip={ip} "
            f"method=GET size='{len(response.content) / 1024:.2f} KiB' "
            f"status={response.status_code} uri={url_to_fetch} "
            f"rate_limit_remaining={remaining}"
        )
        logger.info(log_msg)

        if response.status_code == 304:
            logger.info(
                f"Using cached data for URL: {url_to_fetch}")
            return jsonify(json.loads(cached_resp["data"]))
        elif response.status_code == 200:
            await set_to_cache(url_to_fetch, response.json(), response.headers.get('ETag', ''))
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Upstream API error', 'message': response.text}), response.status_code

    except httpx.RequestError as e:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        log_message = f"Invalid request ip={ip} error={str(e)} uri={request.full_path}"
        logger.warning(log_message)
        return jsonify(error="Invalid request", detail=str(e)), 400

    except ValueError as e:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        log_message = f"Invalid parameter ip={ip} error={str(e)} uri={request.full_path}"
        logger.warning(log_message)
        return jsonify(error="Invalid parameter", detail=str(e)), 400


@app.route('/ping', methods=["GET"])
async def ping():
    return jsonify({'status': 'ok', 'message': 'Service is up and running'})


if __name__ == "__main__":
    app.run(port=5000)
