"""
oauthlib.oauth2.rfc8628
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 Device Authorization RFC8628.
"""

import logging
from oauthlib.oauth2.rfc8628.errors import SlowDownError, AuthorizationPendingError, ExpiredTokenError

log = logging.getLogger(__name__)
