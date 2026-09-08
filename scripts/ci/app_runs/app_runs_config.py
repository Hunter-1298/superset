# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Superset configuration for the `app-runs` CI integration check.

Mounted at ``/app/pythonpath/superset_config.py`` inside the unmodified ``ci``
image. Metadata lives in Postgres (``postgresql+psycopg2``), Celery uses Redis
as broker and result backend, and SQL Lab async results are stored in Redis so
the check can prove that the worker path, not only the web path, works.
"""

from __future__ import annotations

import os

from flask_caching.backends.rediscache import RedisCache

SECRET_KEY = os.environ["SUPERSET_SECRET_KEY"]

DATABASE_USER = os.environ.get("DATABASE_USER", "superset")
DATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]
DATABASE_HOST = os.environ.get("DATABASE_HOST", "postgres")
DATABASE_PORT = os.environ.get("DATABASE_PORT", "5432")
DATABASE_DB = os.environ.get("DATABASE_DB", "superset")

SQLALCHEMY_DATABASE_URI = (
    f"postgresql+psycopg2://{DATABASE_USER}:{DATABASE_PASSWORD}"
    f"@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
)

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_CELERY_DB = 0
REDIS_RESULTS_DB = 1
REDIS_CACHE_DB = 2
REDIS_CELERY_RESULTS_DB = 3


class CeleryConfig:  # pylint: disable=too-few-public-methods
    """Redis broker + result backend; SQL Lab tasks only."""

    broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
    result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_RESULTS_DB}"
    imports = ("superset.sql_lab",)
    worker_prefetch_multiplier = 1
    task_acks_late = False
    task_annotations = {
        "sql_lab.get_sql_results": {"rate_limit": "100/s"},
    }


CELERY_CONFIG = CeleryConfig

RESULTS_BACKEND = RedisCache(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_RESULTS_DB,
    key_prefix="superset_results",
)

CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_CACHE_DB,
}
DATA_CACHE_CONFIG = CACHE_CONFIG
THUMBNAIL_CACHE_CONFIG = CACHE_CONFIG

SQLLAB_ASYNC_TIME_LIMIT_SEC = 120
