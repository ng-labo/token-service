import logging, os, time, traceback
from typing import (
    Any,
    Awaitable,
    Dict,
    Optional,
    Tuple,
)

import tornado.web
import tokenservice
from tornado.httputil import url_concat
from tokenservice.service import Service
from tokenservice.token import TokenService

import auth_github
from tornado.auth import GoogleOAuth2Mixin
from tornado.auth import TwitterMixin

from utils import json_encode, json_decode

import logging
logger = logging.getLogger("token-service")
logger.setLevel(logging.DEBUG)

class BaseRequestHandler(tornado.web.RequestHandler):
    def initialize(self, service: Service, config: Dict) -> None:
        self.service = service
        self.config = config
        self.WEBCONTEXTPATH = config.get('webcontextpath') and config['webcontextpath'] or ""

    def prepare(self) -> Optional[Awaitable[None]]:
        msg = 'REQUEST: {method} {uri} ({ip})'.format(
            method=self.request.method,
            uri=self.request.uri,
            ip=self.request.remote_ip
        )
        logger.info(msg)

        return super().prepare()

    def on_finish(self) -> None:
        super().on_finish()

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        body = {
            'method': self.request.method,
            'uri': self.request.path,
            'code': status_code,
            'message': self._reason
        }

        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            # in debug mode, send a traceback
            trace = '\n'.join(traceback.format_exception(*kwargs['exc_info']))
            body['trace'] = trace

        self.finish(body)

    def get_current_user(self):
        user_json = self.get_secure_cookie("user")
        if not user_json:
            return None
        return json_decode(user_json)


class DefaultRequestHandler(BaseRequestHandler):
    def initialize(self, status_code, message):
        self.set_status(status_code, reason=message)

    def prepare(self) -> Optional[Awaitable[None]]:
        raise tornado.web.HTTPError(
            self._status_code, reason=self._reason
        )


class MainHandler(BaseRequestHandler):
    async def get(self):
        if self.current_user:
            id = self.current_user["login"]
            mytoken, expire = await self.service.get_or_create_token(id)
            self.render("main.html", github_name=self.current_user["name"],
                                     github_id=id, mytoken=mytoken,
                                     mytoken_expire=time.asctime(time.localtime(expire)))
        else:
            self.render("login.html")


class GithubOAuth2LoginHandler(BaseRequestHandler, auth_github.GithubMixin):
    async def get(self):
        redirect_uri = url_concat(
            self.config['oauth_url'], {"next": self.get_argument('next', '/')})
        if self.get_argument("code", False):
            user = await self.get_authenticated_user(
                redirect_uri=redirect_uri,
                client_id=self.config["client_id"],
                client_secret=self.config["client_secret"],
                code=self.get_argument("code"))
            if user:
                logger.info('logged in user from github: ' + user["name"])
                self.set_signed_cookie("user", json_encode(user))
            else:
                self.clear_cookie("user")
            self.redirect(self.get_argument("next", "/"))
            return
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.config["client_id"],
            extra_params={"scope": self.config['scope']})


class GoogleOAuth2LoginHandler(BaseRequestHandler, GoogleOAuth2Mixin):
    def initialize(self, service: Service, config: Dict)-> None:
        BaseRequestHandler.initialize(self, service, config)
        self.settings['google_oauth'] = {}
        self.settings['google_oauth']['key'] = config['client_id']
        self.settings['google_oauth']['secret'] = config['client_secret']

    async def get(self):
        if not self.get_argument('code', False):
            return self.authorize_redirect(
                redirect_uri=self.config['oauth_url'],
                client_id=self.config['client_id'],
                scope=['profile', 'email'],
                response_type='code',
                extra_params={'approval_prompt': 'auto'})

        access_reply = await self.get_authenticated_user(
            redirect_uri=self.config['oauth_url'],
            code=self.get_argument('code'))

        httpc = self.get_auth_http_client()
        resp = await httpc.fetch(
            url_concat(
                self._OAUTH_USERINFO_URL,
                {'access_token': access_reply['access_token']},
            )
        )

        user = json_decode(resp.body.decode())
        if user:
            logger.info('logged in user from google: ' + user["email"])
            user['login'] = user['email']
            self.set_signed_cookie('user', json_encode(user))
        else:
            self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))


class TwitterOAuthLoginHandler(BaseRequestHandler, TwitterMixin):
    def initialize(self, service: Service, config: Dict)-> None:
        BaseRequestHandler.initialize(self, service, config)
        self.settings['twitter_consumer_key'] = config['client_id']
        self.settings['twitter_consumer_secret'] = config['client_secret']

    async def get(self):
        if self.get_argument("oauth_token", None):
            user = await self.get_authenticated_user()
            # Save the user using e.g. set_signed_cookie()
            if user:
                # their cookie are too many !!!
                cookie = {}
                cookie['username'] = user['username']
                cookie['id'] = user['id']
                cookie['login'] = user['username']
                cookie['name'] = user['username']
                cookie['access_token'] = user['access_token']
                logger.info('logged in user from twitter: ' + cookie['username'])
                self.set_signed_cookie("user", json_encode(cookie))
            else:
                self.clear_cookie("user")
            self.redirect(self.get_argument("next", "/"))
            return
        else:
            await self.authorize_redirect()


class LogoutHandler(BaseRequestHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))


class UserQueryHandler(BaseRequestHandler):
    async def get(self, id):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        body = {}
        body['id'] = str(id)
        token = self.get_argument("token", False)
        logger.debug("token={}".format(token))
        if token and self.service.isvalid(id, token):
            body['result'] = 'ok'
        else:
            body['result'] = 'false'
        self.write(body)


def log_function(handler: tornado.web.RequestHandler) -> None:
    status = handler.get_status()
    request_time = 1000.0 * handler.request.request_time()

    msg = 'RESPOSE: {status} {method} {uri} ({ip}) {time}ms'.format(
        status=status,
        method=handler.request.method,
        uri=handler.request.uri,
        ip=handler.request.remote_ip,
        time=request_time,
    )
    logger.info(msg)


def make_tokenservice_app(
    config: Dict,
    debug: bool
) -> Tuple[Service, tornado.web.Application]:
    service = TokenService(config)
    app_config = config['app']

    ui_contents = tokenservice.TOKEN_SERVICE_ROOT_DIR + '/ui-contents'

    service_endpoins = [
        (r"/ui/(.*)?", tornado.web.StaticFileHandler, {'path': ui_contents}),
        (r"/", MainHandler, dict(service=service, config=app_config)),
        (r"/oauth", GithubOAuth2LoginHandler, dict(service=service, config=app_config)),
        (r"/logout", LogoutHandler, dict(service=service, config=app_config)),
        (r"/query/(?P<id>[a-zA-Z0-9-]+)/?", UserQueryHandler, dict(service=service, config=app_config)),
    ]
    if config.get('oauth2') and config['oauth2'].get('github'):
        cfg = app_config.copy()
        cfg.update(config['oauth2']['github'])
        service_endpoins.append((r"/oa2github", GithubOAuth2LoginHandler,
                                                dict(service=service, config=cfg)))
    if config.get('oauth2') and config['oauth2'].get('google'):
        cfg = app_config.copy()
        cfg.update(config['oauth2']['google'])
        service_endpoins.append((r"/oa2google", GoogleOAuth2LoginHandler,
                                                dict(service=service, config=cfg)))

    if config.get('oauth') and config['oauth'].get('twitter'):
        cfg = app_config.copy()
        cfg.update(config['oauth']['twitter'])
        service_endpoins.append((r"/oatwitter", TwitterOAuthLoginHandler,
                                                dict(service=service, config=cfg)))

    app = tornado.web.Application(
        service_endpoins,
        compress_response=True,  # compress textual responses
        #log_function=log_function,  # log_request() uses it to log results
        serve_traceback=debug,  # it is passed on as setting to write_error()
        default_handler_class=DefaultRequestHandler,
        default_handler_args={
            'status_code': 404,
            'message': 'Unknown Endpoint'
        },
        cookie_secret=os.urandom(32),
        xsrf_cookies=True,
        debug=True,
        autoescape=None,
        static_path=ui_contents,
        template_path=ui_contents
    )

    return service, app
