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
import tokenservice
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

    ui_contents = tokenservice.TOKEN_SERVICE_ROOT_DIR + '/ui-contents'

    app = tornado.web.Application(
        [
            # service endpoints
            (r"/ui/(.*)?", tornado.web.StaticFileHandler, {'path': ui_contents}),
            (r"/", MainHandler, dict(service=service, config=app_config)),
            (r"/oauth", GithubOAuth2LoginHandler, dict(service=service, config=app_config)),
            (r"/logout", LogoutHandler, dict(service=service, config=app_config)),
            (r"/query/(?P<id>[a-zA-Z0-9-]+)/?", UserQueryHandler, dict(service=service, config=app_config)),
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
        autoescape=None,
        static_path=ui_contents,
        template_path=ui_contents
    )

    return service, app
