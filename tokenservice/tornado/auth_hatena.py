#!/usr/bin/env python3

from urllib.parse import urlencode
from typing import Any, cast, Dict, Optional

from tornado.auth import OAuthMixin
from tornado.escape import parse_qs_bytes, native_str
from tornado.httputil import url_concat
from tornado.web import RequestHandler

from utils import json_encode, json_decode

class HatenaMixin(OAuthMixin):
    """hatena authentication using OAuth."""

    _OAUTH_REQUEST_TOKEN_URL = "https://www.hatena.ne.jp/oauth/initiate"
    _OAUTH_ACCESS_TOKEN_URL = "https://www.hatena.ne.jp/oauth/token"
    _OAUTH_AUTHENTICATE_URL = "https://www.hatena.ne.jp/oauth/authorize"

    async def authorize_redirect(self, callback_uri: Optional[str] = None) -> None:
        http = self.get_auth_http_client()
        u = self._oauth_request_token_url(callback_uri=callback_uri)
        response = await http.fetch(u)
        self._on_request_token(self._OAUTH_AUTHENTICATE_URL, None, response)

    def _oauth_consumer_token(self) -> Dict[str, Any]:
        handler = cast(RequestHandler, self)
        handler.require_setting("hatena_consumer_key", "Hatena OAuth")
        handler.require_setting("hatena_consumer_secret", "Hatena OAuth")
        return dict(
            key=handler.settings["hatena_consumer_key"],
            secret=handler.settings["hatena_consumer_secret"],
        )

    async def _oauth_get_user_future(self, access_token: Dict[str, Any]) -> Dict[str, Any]:
        # access_token = {'key': '...', 'secret': '...', 'url_name': '...', 'display_name': '...'}

        #
        # TODO retrive and update user data from https://n.hatena.ne.jp/applications/my.json
        #

        return { "access_token": access_token, "display_name" : access_token['display_name'] }

