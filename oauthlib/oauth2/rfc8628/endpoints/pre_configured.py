from oauthlib.oauth2 import TokenEndpoint
from oauthlib.oauth2.rfc8628.endpoints.device_authorization import (
    DeviceAuthorizationEndpoint,
)
from typing import Callable

class DeviceApplicationServer(DeviceAuthorizationEndpoint, TokenEndpoint):
    """An all-in-one endpoint featuring Authorization code grant and Bearer tokens."""

    def __init__(
        self,
        request_validator,
        interval,
        verification_uri,
        user_code_generator: Callable[[None], str] = None,
        **kwargs,
    ):
        """Construct a new web application server.
        :param request_validator: An implementation of
                                  oauthlib.oauth2.rfc8626.RequestValidator.
        :param verification_uri: the verification_uri to be send back.
        :param user_code_generator: a callable that allows the user code to be configured.
        """
        DeviceAuthorizationEndpoint.__init__(
            self,
            request_validator,
            verification_uri=verification_uri,
            interval=interval,
            user_code_generator=user_code_generator,
        )