import os
from datetime import timedelta

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.11/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'dev only!'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'privacyscore.api',
    'privacyscore.backend',
    'privacyscore.evaluation',
    'privacyscore.frontend',
    'privacyscore.scanner',
    #'privacyscore.analysis',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'widget_tweaks',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'privacyscore.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'privacyscore.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'privacy_score',
        'USER': 'privacyscore',
        'PASSWORD': 'privacyscore',
        'HOST': 'localhost',
        'PORT': '',
    }
}
if os.environ.get('NO_DB'):
    # do not enable database on this worker
    DATABASES = {}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
        'LOCATION': '127.0.0.1:11211',
        'OPTIONS': {
            'server_max_value_length': 1024 * 1024 * 5,
        }
    }
}
CACHE_DEFAULT_TIMEOUT_SECONDS = 1800


# Password validation
# https://docs.djangoproject.com/en/1.11/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/1.11/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_ROOT = '/var/www/privacyscore/static/'

STATIC_URL = '/static/'

MEDIA_URL = '/media/'


LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

from kombu import Exchange, Queue
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_SERIALIZER = 'msgpack'
CELERY_RESULT_SERIALIZER = 'msgpack'
CELERY_ACCEPT_CONTENT = ['msgpack']
CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/0'
CELERY_DEFAULT_QUEUE = 'master'
CELERY_QUEUES = (
    Queue('master', Exchange('master'), routing_key='master'),
    Queue('slave', Exchange('slave'), routing_key='slave'),
)


SCAN_REQUIRED_TIME_BEFORE_NEXT_SCAN = timedelta(minutes=28)
SCAN_SUITE_TIMEOUT_SECONDS = 200
SCAN_TOTAL_TIMEOUT = timedelta(hours=8)
SCAN_TEST_BASEPATH = os.path.join(BASE_DIR, 'tests')
SCAN_LISTS_PER_PAGE = 30

# The base modules containing the test suites. You usually do not want to
# change this.
TEST_SUITES_BASEMODULES = [
    'privacyscore.test_suites',
]

# The list of the test names to use. Test names may not be used multiple times.
# See the example test suite for documentation of the test module interface.
SCAN_TEST_SUITES = [
    ('network', {
        'country_database_path': os.path.join(
            SCAN_TEST_BASEPATH, 'vendor/geoip/GeoLite2-Country.mmdb'),
    }),
    ('openwpm', {
        'scan_basedir': '/tmp/openwpm-scans',
        'virtualenv_path': os.path.join(BASE_DIR, 'tests/vendor/OpenWPM/.pyenv'),
    }),
    ('serverleak', {}),
    ('testssl_https', {}),
    ('testssl_mx', {}),
]

RAW_DATA_UNCOMPRESSED_TYPES = [
    'image/png',
    'image/jpeg',
]
RAW_DATA_DB_MAX_SIZE = 4000
RAW_DATA_DIR = os.path.join(BASE_DIR, 'raw_data')
RAW_DATA_DELETE_AFTER = timedelta(days=10)

SCAN_SCHEDULE_DAEMON_SLEEP = 60



# debug toolbar
if DEBUG:
    INSTALLED_APPS += ['debug_toolbar']
    MIDDLEWARE = [
        'debug_toolbar.middleware.DebugToolbarMiddleware'] + MIDDLEWARE
    INTERNAL_IPS = ['127.0.0.1']