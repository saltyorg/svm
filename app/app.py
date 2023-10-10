import os
import logging
import requests
import redis
import apprise
import json
from flask import Flask, request, jsonify, make_response
from datetime import datetime

# Development Configurations
DEV_CONFIG = {
    'GITHUB_PATS': 'YOUR_DEV_PAT1,YOUR_DEV_PAT2',
    'APPRISE_URL': 'YOUR_DEV_APPRISE_URL',
    'API_USAGE_THRESHOLD': 50,
    'REDIS_HOST': 'localhost'
}

is_development = os.environ.get('FLASK_ENV') == 'development'

# Set configurations
if is_development:
    ACCESS_TOKENS = DEV_CONFIG['GITHUB_PATS'].split(',')
    APPRISE_URL = DEV_CONFIG['APPRISE_URL']
    API_USAGE_THRESHOLD = DEV_CONFIG['API_USAGE_THRESHOLD']
    REDIS_HOST = DEV_CONFIG['REDIS_HOST']
else:
    for var in ['GITHUB_PATS', 'APPRISE_URL', 'API_USAGE_THRESHOLD', 'REDIS_HOST']:
        if not os.environ.get(var):
            raise EnvironmentError(f"{var} not set in environment variables!")
    ACCESS_TOKENS = os.environ['GITHUB_PATS'].split(',')
    APPRISE_URL = os.environ['APPRISE_URL']
    API_USAGE_THRESHOLD = int(os.environ['API_USAGE_THRESHOLD'])
    REDIS_HOST = os.environ['REDIS_HOST']

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
current_token_idx = 0

ap = apprise.Apprise()
ap.add(APPRISE_URL)

redis_client = redis.StrictRedis(host=REDIS_HOST, port=6379, db=0, decode_responses=True)


def get_from_cache(key):
    return redis_client.hgetall(key)


def set_to_cache(key, data, etag):
    redis_client.hset(key, mapping={"data": json.dumps(data), "etag": etag})
    redis_client.expire(key, 86400)  # cache for 24 hours


def send_notification(title, message):
    ap.notify(
        body=message,
        title=title,
    )


@app.route('/version', methods=["GET"])
def proxy():
    global current_token_idx

    try:
        url_to_fetch = request.args.get('url')
        if not url_to_fetch:
            raise ValueError("url parameter is required")

        cached_resp = get_from_cache(url_to_fetch)

        token = ACCESS_TOKENS[current_token_idx]
        current_token_idx = (current_token_idx + 1) % len(ACCESS_TOKENS)

        headers = {'Authorization': f'token {token}'}

        if cached_resp and "etag" in cached_resp:
            headers['If-None-Match'] = cached_resp["etag"]

        response = requests.get(url_to_fetch, headers=headers)
        remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        log_msg = (
            f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} "
            f"Request processed duration={response.elapsed.total_seconds():.6f}s "
            f"ip={ip} "
            f"method=GET size='{len(response.content) / 1024:.2f} KiB' "
            f"status={response.status_code} uri={url_to_fetch} "
            f"rate_limit_remaining={remaining}"
        )
        logger.info(log_msg)

        if response.status_code == 304:
            logger.info(f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} Using cached data for URL: {url_to_fetch}")
            return jsonify(json.loads(cached_resp["data"]))
        elif response.status_code == 200:
            set_to_cache(url_to_fetch, response.json(), response.headers.get('ETag', ''))
            return jsonify(response.json())
        else:
            return make_response(jsonify({'error': 'Upstream API error', 'message': response.text}), response.status_code)

    except requests.exceptions.RequestException as e:
        request_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        log_message = f"{request_time} WRN Invalid request ip={ip} error={str(e)} uri={request.full_path}"
        logger.warning(log_message)
        return jsonify(error="Invalid request", detail=str(e)), 400

    except ValueError as e:
        request_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        log_message = f"{request_time} WRN Invalid parameter ip={ip} error={str(e)} uri={request.full_path}"
        logger.warning(log_message)
        return jsonify(error="Invalid parameter", detail=str(e)), 400


if __name__ == "__main__":
    app.run(port=5000)
