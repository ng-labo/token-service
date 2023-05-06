#!/usr/bin/env python

import json
from urllib.parse import urlencode
from typing import Any, Dict

from tornado.auth import OAuth2Mixin
from tornado.escape import to_basestring, parse_qs_bytes, native_str
from tornado.httputil import url_concat


def json_encode(value):
    return json.dumps(value).replace("</", "<\\/")


def json_decode(value):
    return json.loads(to_basestring(value))


class GithubMixin(OAuth2Mixin):
    """Github authentication using OAuth2."""

    _OAUTH_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
    _GITHUB_API_URL = "https://api.github.com"

    async def get_authenticated_user(self, redirect_uri, client_id,
                   client_secret, code, extra_fields=None) -> Dict[str, Any]:
        httpc = self.get_auth_http_client()

        fields = set(["id", "login", "name", "email", "avatar_url"])
        if extra_fields:
            fields.update(extra_fields)

        body = urlencode({
                "redirect_uri": redirect_uri,
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "extra_params": extra_fields
            })

        response = await httpc.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                   method="POST", body=body,
                   headers={'Content-Type': 'application/x-www-form-urlencoded'})

        if response.error:
            return {"error": str(response.error)}

        args = dict()
        for k, v in parse_qs_bytes(native_str(response.body)).items():
            args[k] = v[-1].decode()

        if "error" in args:
            print("error in response")
            return {"error": args['error']}

        access_token = args["access_token"]

        res = await self.github_request(httpc, "/user", access_token)
        if res.error:
            return {"error": str(res.error)}

        if res.body is None:
            return {"error": "no data"}

        fieldmap = json_decode(res.body.decode())
        fieldmap.update({"access_token": access_token})

        return fieldmap

    """
    def get_auth_http_client(self):
        return tornado.httpclient.AsyncHTTPClient()
    """

    def github_request(self, http_client, path, access_token=None,
                   method="GET", body=None, **args):
        url = GithubMixin._GITHUB_API_URL + path

        all_args = {}
        headers = {}

        if access_token:
            headers["Authorization"] = "token " + access_token

        all_args.update(args)

        if all_args:
            url = url_concat(url, all_args)

        if body is not None:
            body = json_encode(body)

        return http_client.fetch(url, method=method, body=body, headers=headers)
