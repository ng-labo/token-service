from .service import Service
from typing import Dict, Tuple
import uuid
import datetime, time
import os, os.path

#from tokenservice.datastore import DataStore

import logging
logger = logging.getLogger("nglogger-service")
logger.setLevel(logging.DEBUG)

D = """1683731637,35.544765,139.667310,100,0,0,0.000,5.400000,gps,0,1,0
1683734029,35.544843,139.667327,100,0,0,0.000,5.200000,gps,0,1,0
1683736421,35.544823,139.667363,100,0,0,0.000,5.400000,gps,0,1,0
1683738813,35.544892,139.667365,100,0,0,0.000,5.500000,gps,0,1,0
1683741195,35.544885,139.667318,100,0,0,0.000,5.300000,gps,0,1,0
1683743587,35.544802,139.667268,100,0,0,0.000,5.300000,gps,0,1,0
1683745979,35.544885,139.667310,100,0,0,0.000,5.400000,gps,0,1,0
1683748361,35.544902,139.667428,100,0,0,0.000,5.400000,gps,0,1,0
1683750754,35.544857,139.667370,100,0,0,0.000,5.400000,gps,0,1,0"""

#CONFIG_LOG_BASE = "/home/nao/github.com/token-service/data"

log_aday_templ = "%s/%s/log.v2.%s"
log_hist_templ = "%s/%s/loghis"

class LoggerService(Service):

    def __init__(
        self,
        config: Dict
    ) -> None:
        self.config = config
        self.log_root_dir = config['datadir']
        #self.db = DataStore(config['db'])

    def checkinfirst(self, id):
        userdir = self.log_root_dir + "/" + id
        if not os.path.exists(userdir):
            os.mkdir(userdir)
        return True

    def isvalid(self, id, token):
        return True

    def logdata(self, id, logbody):
        ret = False
        #logger.debug(logbody)
        balktext = logbody.decode('utf8')
        day = datetime.datetime.today().strftime('%y%m%d')
        with open(log_aday_templ % (self.log_root_dir, id, day), "a") as logfile:
            try:
                logfile.write(balktext)
                ret = True
                hisfn = log_hist_templ % (self.log_root_dir, id)
                hisdata = open(hisfn).read()
                if hisdata.find(day) == -1:
                    open(hisfn, "a").write(day + '\n')
            except:
                pass
        return ret
        #for line in logbody.decode('utf8').split('\n'):
            
    def getloggeddays(self, id):
        with open(log_hist_templ % (self.log_root_dir, id)) as hisfile:
            days = hisfile.read().split('\n')[:-1]
            return days
        return []


    def getlog(self, id, dt):
        ret = []
        with open(log_aday_templ % (self.log_root_dir, id, dt), "r") as logfile:
            while True:
                ln = logfile.readline()
                if not ln: break
                if ln.startswith('#'): continue
                o = ln.split(',')
                if len(o)<8: break
                p = {}
                ts = int(o[0])
                #if ts<=lastts: continue
                #if ignore_inaccracy and o[9] == '1' : continue
                if o[8]=='gps' and float(o[7])>1000.0: continue
                if o[8]=='network' and float(o[7])>10000.0: continue
                p['lat'] = o[1]
                p['lon'] = o[2]
                p['dt'] = datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d-%H%M%S')
                p['owner'] = ",".join(o[3:])
                ret.append(p)

        return ret
