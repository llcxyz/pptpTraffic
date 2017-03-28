# coding:utf-8
import pyshark
import threading
import pyinotify
import time
import os
import logging
import re
import json

from datetime import datetime
logging.basicConfig(level=logging.INFO)

import urllib

class WatchLogUser(threading.Thread):
    r_pptpd = re.compile(r"pppd\[(\d+)\]")
    r_ppp_ipup = re.compile(r"(.+?) [a-zA-Z0-9\-\.]+ pppd\[\d+\]: pptpd-logwtmp.so ip-up ([a-z0-9]+) ([^\s]+) (\d+\.\d+\.\d+\.\d+)")
    r_ppp_close = re.compile(r"Sent (\d+) bytes, received (\d+) bytes")
    r_ppp_remoteip4 = re.compile(r"remote IP address (\d+\.\d+\.\d+\.\d+)")
    r_ppp_localip4 = re.compile(r"local IP address (\d+\.\d+\.\d+\.\d+)")
    r_ppp_exit = re.compile(r"Exit.")
    fmt_timestamp = "%b %d %H:%M:%S"
    r_xl2tp_connect = re.compile(r"Connect: ppp(\d+) <--> /dev/pts/(\d+)")
    r_pptp_connect = re.compile(r"(.+?) [a-zA-Z0-9\-\.]+ pppd\[\d+\]: Connect: ppp(\d+) <--> /dev/pts/(\d+)")
    r_xl2tp_resp = re.compile(r"rcvd \[(\S.*) Response (\S.*) name = \"(\S.*)\"\]")
    r_xl2tp_established = re.compile(r"(\S.*) xl2tpd\[\d+\]: Call established with (\d+\.\d+\.\d+\.\d+)(\S.*)")
    r_xl2tp_startup = re.compile(r"Script /etc/ppp/ip-up started (\S.*)")

    def __init__(self, logfile='/var/log/messages', xl2tplog='/var/log/xl2tpd.log', reporter=None):
        threading.Thread.__init__(self, name="watch_%s" % (logfile.replace("/","_")))
        self.log = logging.getLogger("WatchLogUser")
        self.logfile = logfile
        self.xl2tplog = xl2tplog
        self.activesessions = {}
        self.xl2tp_session = {}
        self.last_session = None
        self.last_xl2tp_remote_ip = None

        self.mhandler = reporter
        # pptp
        self.file = open(self.logfile, 'r')
        st_results = os.stat(self.logfile)
        st_size = st_results[6]
        self.file.seek(st_size)

        # xl2tp
        self.l2tpfile = open(self.xl2tplog, 'r')
        st_results = os.stat(self.xl2tplog)
        st_size = st_results[6]
        self.l2tpfile.seek(st_size)

        self.wm = pyinotify.WatchManager()
        self.notifier = pyinotify.Notifier(self.wm)
        self.wm.add_watch(self.logfile, pyinotify.IN_MODIFY, self.process_IN_MODIFY_pptp)
        self.wm.add_watch(self.xl2tplog, pyinotify.IN_MODIFY,self.process_IN_MODIFY_xl2tp)
        self.setDaemon(True)
        self.log.info("create watchloguser ")

    def run(self):
        self.log.info("start watching log user....")
        self.notifier.loop()

    def process_IN_MODIFY_pptp(self, event):
        line = True
        while line:
            if line:
                line = self.file.readline()
                if line:
                    self.process_line(line)
            else:
                break

    def process_IN_MODIFY_xl2tp(self, event):
        line = True
        while line:
            if line:
                line = self.l2tpfile.readline()
                if line:
                    self.process_xl2tp_line(line)
            else:
                break

    def process_xl2tp_line(self, line):
        # self.log.debug("xl2tp ->> %s" % line)
        match = self.r_xl2tp_connect.search(line)
        if match:
            iface = match.group(1)
            iface = "ppp%s" % iface
            tty = match.group(2)
            tty = "/dev/pts/%s" % tty
            self.log.info("start xl2tp interface[%s]" % iface)
            self.xl2tp_session.setdefault(iface, {
                'iface': iface, 'tty': tty, 'username': None,
                'ip4': self.last_xl2tp_remote_ip,
                'watcher': None})
            self.last_session = self.xl2tp_session[iface]

        if self.last_session:
            match = self.r_xl2tp_resp.search(line)
            if match:
                username = match.group(3)
                self.last_session['username'] = username
                self.log.info("xl2tp: find user name [%s] " % username)
                self.log.info("xl2tp: current session = %s" % self.last_session)

            match = self.r_xl2tp_startup.search(line)
            if match:
                self.log.debug(" user[%s] if up %s" % (self.last_session['username'], self.last_session['iface']))

                wat = WatchInterface(self.last_session['username'], self.last_session['ip4'],
                                     self.last_session['iface'], handler=self.mhandler)
                self.last_session['watcher'] = wat
                wat.start()

    def process_line(self, line):
        # self.log.debug("pptp ->> %s" % line)
        # xl2tp
        match = self.r_xl2tp_established.search(line)
        if match:
            self.last_xl2tp_remote_ip = match.group(2)

        match = self.r_pptpd.search(line)
        if match:
            pid = match.group(1)
            newconnection = (pid not in self.activesessions)
            self.activesessions.setdefault(pid, {
                "interface":      None,
                "username":       None,
                "ip4":            None,
                "ppp_remoteip4":  None,
                "ppp_localip4":   None,
                "total":          0,
                "rx":             0,
                "tx":             0,
                "status":         None,
                "timestamp_open": None,
                'watcher': None,
                })

            session = self.activesessions[pid]

            #  remote ip v4
            match = self.r_pptp_connect.search(line)
            if match:
                session['interface'] = "ppp%s" % match.group(2)

            match = self.r_ppp_remoteip4.search(line)
            if match:
                session['ppp_remoteip4'] = match.group(1)

            m_ipup = self.r_ppp_ipup.search(line)
            if m_ipup:
                timestamp = m_ipup.group(1)
                interface = m_ipup.group(2)
                username = m_ipup.group(3)
                ip4 = m_ipup.group(4)
                session['status'] = 'open'
                session['timestamp_open'] = datetime.now().strftime(self.fmt_timestamp)
                session['interface'] = interface
                session['username'] = username
                session['ip4'] = ip4
                self.log.debug(" user[%s] if up %s" % (username, interface))
                wat = WatchInterface(username, ip4, interface, handler=self.mhandler)
                session['watcher'] = wat
                wat.start()

            # PPTP session closed
            m_close = self.r_ppp_close.search(line)
            if m_close:
                tx = int(m_close.group(1))
                rx = int(m_close.group(2))
                session['status'] = 'closed'
                session['tx'] += tx
                session['rx'] += rx
                session['total'] += tx + rx
                self.log.debug(" user[%s] if closed %s" % (session['username'], session['interface']))
            m_exit = self.r_ppp_exit.search(line)
            if m_exit:
                # After process exits, remove PID from sessions
                # because same PID will be used again
                # (after long uptime, or reboot)
                # and we dont want stats to be merged!
                self.log.debug(" user[%s] if pptpd exit %s" % (session['username'], pid))
                wat = self.activesessions[pid]['watcher']
                if wat:
                    wat.stop()
                iface = self.activesessions[pid]['interface']
                if iface in self.xl2tp_session:
                    wat = self.xl2tp_session[iface]['watcher']
                    if wat:
                        wat.stop()

                    del self.xl2tp_session[iface]

                del self.activesessions[pid]
            #print session
            # print json.dumps(self.activesessions, indent=4)


class WatchInterface(threading.Thread):
    def __init__(self, user=None, remoteip=None, interface="ppp0", bpf_filter=None, display_filter=None, handler=None):
        self.user = user
        self.remoteip = remoteip
        threading.Thread.__init__(self, name="watch_%s" % interface)
        self.log = logging.getLogger("Watch_%s_%s" % (user, interface))
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.display_filter = display_filter

        self.handler = handler
        if not bpf_filter:
            self.bpf_filter = '(tcp port 80 or tcp port 8080) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
        if not display_filter:
            self.display_filter = 'http.request.method == "POST" || http.request.method == "GET"'
        self.setDaemon(True)


        self.log.info("watch interface created")

    def run(self):
        self.capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.bpf_filter,
                                           display_filter=self.display_filter)
        self.log.info("start capature[user=%s, interface=%s, remoteip=%s"%(self.user, self.interface,self.remoteip))
        for packet in self.capture.sniff_continuously():
            src = packet['ip'].src
            dst = packet['ip'].dst
            request_full_uri = ''
            data_text_lines = ''
            user_agent = ''
            json = ''
            #print packet
            if hasattr(packet, 'http'):
                if hasattr(packet.http, 'request_full_uri'):
                    request_full_uri = packet.http.request_full_uri
                if hasattr(packet.http, 'user_agent'):
                    user_agent = packet.http.user_agent
            if 'data-text-lines' in packet:
                data_text_lines = packet['data-text-lines']
            if 'json' in packet:
                json = packet['json']
                json.raw_mode = True

            if hasattr(packet,'data_text_lines'):
                # print 'data = ', packet.data_text_lines
                data_text_lines = packet.data_text_lines
            #print '*************************************************'
            #print src
            #print dst
            #print request_full_uri
            #print data_text_lines
            #print '*************************************************'
            if data_text_lines:
                data_text_lines = self.trim(str(data_text_lines))

            if self.handler:
                result = {'user': self.user, 'user_agent': user_agent,
                          'caller_ip': self.remoteip, 'src': src, 'dst': dst, 'request_full_uri':
                    request_full_uri, 'data_text_lines': data_text_lines, 'json': str(json)}
                self.handler.handle(self.user, result)

    def stop(self):
        self.capture.close()
        self.log.info("stop capature!")


    def trim(self, data):
        rline = []
        lines = data.split("\n")
        for line in lines:
            line = line.strip()
            if line.startswith("Layer DATA-TEXT-LINES"):
                continue
            if line.startswith("[truncated]"):
                rline += [self.detect(urllib.unquote(line.strip()))]
            else:
                rline += [self.detect(urllib.unquote(line.strip()))]

        return "\n".join(rline)

    def detect(self, data):
        ret = data
        try:
            data.decode("utf-8")
            return ret
        except Exception,ex:
            try:
                ret = data.decode("gbk")
                return ret
            except Exception,ex:
                pass
        return ret

from zrtc.zrpc import zrpcClient, zService, zServer, zrpcException
import urlparse

class reporter(object):
    def __init__(self, host, port, username, password, db='zvpn'):
        self.log = logging.getLogger("reporter")
        self.host = "127.0.0.1"
        self.port = port
        self.username = username
        self.password = password
        self.serv = zServer(target="tcp://%s:%s" % (host, port), security=False)
        self.service = self.serv.get(db, username, password)
        self.history = self.service.get("http.access.history")

    def handle(self, user, result):
        parseTuple = urlparse.urlparse(result['request_full_uri'])
        result['domain'] = parseTuple.netloc
        result['query'] = parseTuple.query
        result['path'] = parseTuple.path
        result['params'] = parseTuple.params
        print 'user [%s] access ->%s' % (user, result)
        try:
            self.history.submit(user, result)
        except zrpcException, ex:
            self.log.error("submit error(%s)" % ex.message)
        except Exception, ex2:
            self.log.error("submit error(%s)"%ex2.message)

import sys
import signal
import time

if __name__ == "__main__":
    exit1 = False
    def shutdown(signum, sigframe):
        print 'shutdown'
        exit= True
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    # '$1$yk9ZTQGn$75yCRfUp50ZQa.xIpk3Kd0'
    host = sys.argv[1]
    user = sys.argv[2]
    passwd = sys.argv[3]
    db = sys.argv[4]
    rp = reporter(host, 19011, user, passwd, db=db)

    wu = WatchLogUser(reporter=rp)
    wu.start()
    time.sleep(2)
    try:
        while not exit1:
            time.sleep(3)

    except KeyboardInterrupt:
        pass



