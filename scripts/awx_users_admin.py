#!/usr/bin/env python

import requests
import os
import logging
import json
import sys
import datetime
import argparse
import csv
import traceback
from string import Template
from libs.User import *
from libs.Configuration import Configuration
from libs import RestUtils
restAPIResources = os.path.abspath('./resources')


def run():
    logger.info("Authenticating user {}.".format(userid))
    readConfigFile()
    RestUtils.buildEndpoints(0, config)
    createUsers()



# read in user csv file, store in dict no duplicate usernames are allowed, then call api

def createUsers():
    users = {}
    try:
        with open(config.user_csv, newline='') as csvfile:

            header = csv.Sniffer().has_header(open(config.user_csv).read())
            
            if(header):
            
                reader = csv.reader(csvfile.readlines()[1:],delimiter=',')
            
                for user in reader:
                    u = User(user[0],user[1],user[2],user[3],user[4],user[5],user[6])
                    users[u.username] = u
                    
        csvfile.close()
        user_template = Template(open(restAPIResources + "/user.json").read())

        for new_user in users:
            logger.info("Creating user, with username = {}".format(users[new_user].username))
        
            
            user_data = {
                "username": users[new_user].username,
                "firstname": users[new_user].firstname,
                "lastname": users[new_user].lastname,
                "email": users[new_user].email,
                "is_superuser": users[new_user].is_superuser.lower(),
                "is_system_auditor": users[new_user].is_system_auditor.lower(),
                "password": users[new_user].password
            }
            
            response = RestUtils.post_request(headers, "USERS",
                                        user_template.substitute(user_data))

            if(response.status_code == 201):
                logger.info("(OK) - Created.")
               
            else:
                logger.error("Failed to create user.")
                logger.error(response.text)
               

    except Exception as e:
        logger.error(traceback.format_exc())

            

# read in main config file


def readConfigFile():
    logger.info("Reading in configuration file = {}".format(config_file))

    try:
        auth_settings = json.load(open(config_file))

        global config, headers

        config = None

        for x in auth_settings['settings']:
            if (x['userid'] == userid):

                config = Configuration(x['awx_server_url'], x['token'],
                                               x['api_version'], x['userid'],
                                               x['user_csv'])

                break

        if (config == None):
            logger.error(
                "Failed to match authentication settings for userid = {}".
                format(userid))
        else:
            headers = {
                "User-agent": "python-awx-client",
                "Content-Type": "application/json",
                "Authorization": "Bearer {}".format(config.token)
            }
            logger.info(
                "Authentication settings found for userid = {}".format(userid))

    except FileNotFoundError:
        logger.error("Authentication file not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(
            "Failed to parse authentication file, verify the JSON file is correct."
        )
        sys.exit(1)


def initialise_logger():
    # create logger
    logger = logging.getLogger('logger')
    # create console handler and set level to debug
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    # fh = logging.FileHandler(log_path + "/" + "renamer.log",mode='a')
    ch.setLevel(logging.DEBUG)
    # fh.setLevel(logging.DEBUG)
    # create formatter
    formatter = logging.Formatter("%(asctime)s:%(levelname)s > %(message)s",
                                  "%Y-%m-%d %H:%M:%S")
    # add formatter to ch
    ch.setFormatter(formatter)
    # fh.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)
    # logger.addHandler(fh)
    return logger


def main():
    global logger, config_file, userid
    logger = initialise_logger()

    logger.info("Creates AWX user accounts.")

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Ansible AWX User creator.')

    parser.add_argument("--userid",
                        type=str,
                        help="Specify the userid to connect to the AWX API.")

    parser.add_argument("--config",
                        type=str,
                        help="Specify the config json file.")

    args = parser.parse_args()

    if (args.userid is not None and args.config is not None):
        config_file = args.config
        userid = args.userid
        run()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
