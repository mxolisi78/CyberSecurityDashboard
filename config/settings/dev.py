"""
Development settings: verbose errors, SQLite, permissive hosts.
"""

from .base import *  # noqa: F401,F403
from decouple import config, Csv

DEBUG = True

ALLOWED_HOSTS = config(
    "ALLOWED_HOSTS",
    default="127.0.0.1,localhost,0.0.0.0",
    cast=Csv(),
)

# If DATABASE_URL is provided, use Postgres; otherwise fall back to SQLite.
DATABASE_URL = config("DATABASE_URL", default="")

if DATABASE_URL:
    import dj_database_url  # noqa
    DATABASES = {"default": dj_database_url.parse(DATABASE_URL)}
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",  # noqa: F405
        }
    }