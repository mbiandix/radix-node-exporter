#!/usr/bin/env python3

""" Exporter for Radix Node
"""

import argparse
import logging
import requests
import json
from wsgiref.simple_server import make_server
# from prometheus_client import make_wsgi_app, Counter, Gauge
from prometheus_client import make_wsgi_app, Gauge

from os import path
from requests.auth import HTTPBasicAuth
from flatten_json import flatten

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #TODO generate ssl certs and remoe this!

from metrics import metrics
from enums import Env

gauges = {}
for (metric, desc) in metrics:
    gauges[metric] = Gauge("radix_%s" %metric, desc)


def read_metrics():
    gauges["up"].set(0)
    # Query /system/info
    try:
        resp = requests.get("https://%s/system/info" %nginx_endpoint, verify=False, auth=HTTPBasicAuth("admin", nginx_passwd))
        #curl -k -u admin:${RADIXDLT_NGINX_PASSWD} https://nginx/node/validator
        flat_json = flatten(resp.json())
        # for k in flat_json:
        #     print('("%s", "%s"),'%(k,k))
        gauges["up"].set(1)
        for metric, value in flat_json.items():
            if metric in gauges:
                gauges[metric].set(value)
    except Exception as e:
        raise

    # Quey /system/peers
    try:
        resp = requests.get("https://%s/system/peers" %nginx_endpoint, verify=False, auth=HTTPBasicAuth("admin", nginx_passwd))
        gauges["peers_count"].set(len(resp.json()))
    except Exception as e:
        raise

    # query /node/validator
    try:
        resp = requests.post("https://%s/node/validator" %nginx_endpoint, verify=False, auth=HTTPBasicAuth("admin", nginx_passwd))
        #curl -k -u admin:${RADIXDLT_NGINX_PASSWD} https://nginx/node/validator
        json_data = resp.json()
        #flat_json = flatten(json_data)
        #print(flat_json)
        gauges["validator_stakes_count"].set(len(json_data["validator"]["stakes"]))
        gauges["validator_registered"].set(1 if json_data["validator"]["registered"] else 0)
        gauges["validator_totalStake"].set(json_data["validator"]["totalStake"])
    except Exception as e:
        raise

    # Query /system/epochproof
    try:
        resp = requests.get("https://%s/system/epochproof" %nginx_endpoint, verify=False, auth=HTTPBasicAuth("admin", nginx_passwd))
        json_data = resp.json()
        gauges["sigs_count"].set(len(json_data["sigs"])),
        gauges["header_nextValidators_is_included"].set(1 if node_id in [x["address"] for x in json_data["header"]["nextValidators"]] else 0)                                                              
        gauges["header_nextValidators_count"].set(len(json_data["header"]["nextValidators"]))
        gauges["header_nextValidators_stake_min"].set(min([float(x["stake"]) / 1e18 for x in json_data["header"]["nextValidators"]]))
        gauges["header_nextValidators_stake_max"].set(max([float(x["stake"]) / 1e18 for x in json_data["header"]["nextValidators"]]))
    except Exception as e:
        raise

    # Query archive node
    try:
        pass #TODO
    except Exception as e:
        raise


def process_request(environ, start_response):
    if environ['PATH_INFO'] == '/metrics':
        read_metrics()
        return app(environ, start_response)
    else: #elif environ['PATH_INFO'] == '/':
            status = '200 OK'
            headers = [('Content-type', 'text/html; charset=utf-8')]
            start_response(status, headers)
            return [hello_msg.encode("utf-8")]


if __name__ == '__main__':
    ###################################################################
    ############# Arguments parsing ###################################
    ###################################################################
    PARSER = argparse.ArgumentParser(description="Start the Radix Node Exporter.")
    PARSER.add_argument("-d", "--dir", metavar="user-directory",
                        dest="dir", default=path.expanduser("~/node-exporter"),
                        help="directory containing the config, data and logs sub-directories")
    PARSER.add_argument("-e", "--env", dest="env", help="environment to run",
                        choices=["development", "staging", "production"],
                        metavar="environment", default="development")
    PARSER.add_argument("--log-level", dest="log_level", metavar="logging-level",
                        default="info", choices=["info", "debug"],
                        help="the logging level to use")
    PARSER.add_argument("-a", "--passwd", dest="nginx_passwd", metavar="nginx-passwd",
                        help="the admin password for nginx")
    PARSER.add_argument("-p", "--port", dest="port", metavar="listen-port",
                        default=9111, help="the port the application should listen on")
    PARSER.add_argument("-n", "--endpoint", dest="endpoint", metavar="nginx-endpoint",
                        default="nginx", help="the ip of the nginx endpoint")
    PARSER.add_argument("-i", "--id", dest="node_id", metavar="node-id",
                        help="the id of the node", required=True)
    ARGS = PARSER.parse_args()
    LOG_LEVELS = {
        "info": logging.INFO,
        "debug": logging.DEBUG,
    }

    env = Env(ARGS.env)
    nginx_endpoint = ARGS.endpoint
    nginx_passwd = ARGS.nginx_passwd
    listen_port = int(ARGS.port)
    user_dir = ARGS.dir
    log_level = LOG_LEVELS[ARGS.log_level]
    node_id = ARGS.node_id
    hello_msg = "<html>\
                    <head><title>Radix Node Exporter</title></head>\
                    <body>\
                        <h1>Radix Node Exporter</h1>\
                        <p><a href='/metrics'>Metrics</a></p>\
                        <p><a href='https://github.com/mbiandix/radix-node-exporter'>Github</a></p>\
                    </body>\
                </html>"

    # Configure logging
    logging.basicConfig(filename=user_dir + "/logs/app.log", level=log_level,
                        format='%(asctime)s %(message)s', datefmt='[%d.%m.%Y %H:%M:%S] -')
    if env is Env.DEV:
        # For printing to console
        logging.getLogger().addHandler(logging.StreamHandler())

    app = make_wsgi_app()

    # Start up the server to expose the metrics.
    with make_server('', listen_port, process_request) as httpd:
    # with make_server('', listen_port, demo_app) as httpd:
        logging.info("App running on port %s..." %listen_port)
        httpd.serve_forever()

