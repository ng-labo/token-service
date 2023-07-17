import argparse, asyncio, yaml
from typing import Dict

import tornado.web
from tornado.log import enable_pretty_logging

from tokenservice.service import Service
from tokenservice.tornado.app import make_tokenservice_app, logger


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description='Run Token Server'
    )

    parser.add_argument(
        '-d',
        '--debug',
        action='store_true',
        help='turn on debug logging'
    )

    parser.add_argument(
        '-c',
        '--config',
        required=True,
        type=argparse.FileType('r'),
        help='config file for %(prog)s'
    )

    args = parser.parse_args(args)
    return args


def run_server(
    app: tornado.web.Application,
    service: Service,
    config: Dict,
    debug: bool,
):
    name = config['service']['name']
    loop = asyncio.get_event_loop()

    server_config = config['service']['server']

    if server_config.get('httpclient'):
        tornado.httpclient.AsyncHTTPClient.configure(server_config['httpclient'])
    enable_pretty_logging()

    # Start Token service
    service.start()

    # Bind http server to port
    http_server_args = {}
    http_server_args['decompress_request'] = True
    if server_config.get('certfile') and server_config.get('keyfile'):
        http_server_args['ssl_options'] = {
            'certfile': server_config['certfile'],
            'keyfile': server_config['keyfile']}

    port = int(server_config['port'])
    http_server = app.listen(port, '', **http_server_args)
    msg = 'Starting {} on port {} ...'.format(name, port)
    logger.info(msg)

    try:
        # Start asyncio IO event loop
        loop.run_forever()
    except KeyboardInterrupt:
        # signal.SIGINT
        pass
    finally:
        loop.stop()
        msg = 'Shutting down {}...'.format(name)
        logger.info(msg)
        http_server.stop()
        loop.run_until_complete(loop.shutdown_asyncgens())
        service.stop()
        loop.close()
        msg = 'Stopped {}.'.format(name)
        logger.info(msg)


def main(args=parse_args()):
    '''
    Starts the Tornado server
    '''

    config = yaml.load(args.config.read(), Loader=yaml.SafeLoader)

    token_service, token_app = make_tokenservice_app(
        config['service'], args.debug)

    run_server(
        app=token_app,
        service=token_service,
        config=config,
        debug=args.debug,
    )


if __name__ == '__main__':
    main()
