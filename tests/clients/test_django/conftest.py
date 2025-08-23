import os

import django
from django.conf import settings


def pytest_configure():
    if not settings.configured:
        os.environ["DJANGO_SETTINGS_MODULE"] = "tests.django_settings"
        django.setup()
