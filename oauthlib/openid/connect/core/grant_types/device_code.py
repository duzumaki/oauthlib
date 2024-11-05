import json
import logging

from .. import errors
from .base import GrantTypeBase

log = logging.getLogger(__name__)


class DeviceCodeGrant(GrantTypeBase):
    def create_authorization_response(self, request, token_handler):
        headers = self._get_default_headers()
        try:
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            headers.update(e.headers)
            return headers, e.json, e.status_code

        token = token_handler.create_token(request, refresh_token=False)

        for modifier in self._token_modifiers:
            token = modifier(token)

        self.request_validator.save_token(token, request)

        return self.create_token_response(request, token_handler)

    def validate_token_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        for validator in self.custom_validators.pre_token:
            validator(request)

        if not getattr(request, 'grant_type', None):
            raise errors.InvalidRequestError('Request is missing grant type.',
                                             request=request)

        if not request.grant_type == 'urn:ietf:params:oauth:grant-type:device_code':
            raise errors.UnsupportedGrantTypeError(request=request)

        for param in ('grant_type', 'scope'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description='Duplicate %s parameter.' % param,
                                                 request=request)

        log.debug('Authenticating client, %r.', request)
        if not self.request_validator.authenticate_client(request):
            log.debug('Client authentication failed, %r.', request)
            raise errors.InvalidClientError(request=request)
        elif not hasattr(request.client, 'client_id'):
            raise NotImplementedError('Authenticate client must set the '
                                      'request.client.client_id attribute '
                                      'in authenticate_client.')
        # Ensure client is authorized use of this grant type
        breakpoint()
        self.validate_grant_type(request)

        request.client_id = request.client_id or request.client.client_id
        log.debug('Authorizing access to client %r.', request.client_id)
        self.validate_scopes(request)

        for validator in self.custom_validators.post_token:
            validator(request)

    def create_token_response(self, request, token_handler):
        """Return token or error in json format.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param token_handler: A token handler instance, for example of type
                              oauthlib.oauth2.BearerToken.

        If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in `Section 5.1`_.  If the request failed client
        authentication or is invalid, the authorization server returns an
        error response as described in `Section 5.2`_.

        .. _`Section 5.1`: https://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: https://tools.ietf.org/html/rfc6749#section-5.2
        """
        headers = self._get_default_headers()
        try:
            if self.request_validator.client_authentication_required(request):
                if not self.request_validator.authenticate_client(request):
                    raise errors.InvalidClientError(request=request)

            self.validate_token_request(request)

        except errors.OAuth2Error as e:
            headers.update(e.headers)
            return headers, e.json, e.status_code

        token = token_handler.create_token(request, self.refresh_token)

        self.request_validator.save_token(token, request)

        return headers, json.dumps(token), 200