import logging, time
import os, traceback
from typing import (
    Any,
    Awaitable,
    Dict,
    Optional,
    Tuple,
)

import tornado.web
import tornado.websocket
from tornado.httputil import url_concat
from tokenservice.service import TokenService

import auth_github
import logging
logger = logging.getLogger("token-service")
logger.setLevel(logging.DEBUG)


class BaseRequestHandler(tornado.web.RequestHandler):
    def initialize(
        self,
        service: TokenService,
        config: Dict
    ) -> None:
        self.service = service
        self.config = config

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
        return auth_github.json_decode(user_json)


class DefaultRequestHandler(BaseRequestHandler):
    def initialize(self, status_code, message):
        self.set_status(status_code, reason=message)

    def prepare(self) -> Optional[Awaitable[None]]:
        raise tornado.web.HTTPError(
            self._status_code, reason=self._reason
        )


class MainHandler(BaseRequestHandler, auth_github.GithubMixin):
    template = """
    Login User: {}({})
    <p>your token is <input type='text' value='{}' id='token' readonly='readonly' size=48>
    <button onclick="var c=document.getElementById('token');c.select();
         c.setSelectionRange(0, 99999);navigator.clipboard.writeText(c.value);">Copy</button>
    <p>expire in {}
    <p><a href="/logout">Logout</a>
    """
    async def get(self):
        if self.current_user:
            id = self.current_user["login"]
            mytoken, expire = await self.service.get_or_create_token(id)
            self.write(
                MainHandler.template.format(
                    self.current_user["name"], id, mytoken, time.asctime(time.localtime(expire))))
        else:
            self.write('<a href="/oauth">Login</a>')


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
                self.set_secure_cookie("user", auth_github.json_encode(user))
            else:
                self.clear_cookie("user")
            self.redirect(self.get_argument("next", "/"))
            return
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.config["client_id"],
            extra_params={"scope": self.config['scope']})


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

class WebSocketHandler(BaseRequestHandler, tornado.websocket.WebSocketHandler):

    AUTH_WORD_IN_HEADER = "Sec-WebSocket-Protocol"
    agensts = []

    def initialize(
        self,
        service: TokenService,
        config: Dict
    ) -> None:
        self.src = None
        return super().initialize(service, config)

    def _parse_auth(self, auth):
        return [x.strip() for x in auth.split(",")]

    def check_origin(self, origin):
        #logger.info(str(self.request.headers))
        auth = self.request.headers.get(WebSocketHandler.AUTH_WORD_IN_HEADER)
        if auth is None:
            return False
        _, src = self._parse_auth(auth)
        self.src = src
        # isValidToken(_)
        return True

    def open(self):
        for agent in WebSocketHandler.agensts:
            agent.write_message("#{} joined".format(self.src))
        if self not in WebSocketHandler.agensts:
            WebSocketHandler.agensts.append(self)

    def on_close(self):
        if self in WebSocketHandler.agensts:
            WebSocketHandler.agensts.remove(self)
        for agent in WebSocketHandler.agensts:
            agent.write_message("#{} has gone".format(self.src))

    async def on_message(self, message):
        logger.info("#message: {}".format(message))
        if message.startswith("#req"):
            self.write_message(str([agent.src for agent in WebSocketHandler.agensts]))
        #for agent in WebSocketHandler.agensts:
        #    agent.write_message(message)


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
) -> Tuple[TokenService, tornado.web.Application]:
    service = TokenService(config)
    app_config = config['app']

    app = tornado.web.Application(
        [
            # service endpoints
            (r"/", MainHandler, dict(service=service, config=app_config)),
            (r"/oauth", GithubOAuth2LoginHandler, dict(service=service, config=app_config)),
            (r"/logout", LogoutHandler, dict(service=service, config=app_config)),
            (r"/query/(?P<id>[a-zA-Z0-9-]+)/?", UserQueryHandler, dict(service=service, config=app_config)),
            (r"/ws", WebSocketHandler, dict(service=service, config=app_config)),
        ],
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
        autoescape=None
    )

    return service, app
