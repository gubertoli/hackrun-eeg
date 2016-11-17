import asyncore, socket, asynchat, json, threading, time, logging, sys, signal, os, struct
from datetime import datetime
from copy import deepcopy
from threading import Timer, Thread, Event

log = logging.getLogger('HackRUN')
wlog = logging.getLogger('WebServer')

FILE_LISTS = {
    'localhost': ['readme', 'solution'],
    'gateway': ['welcome'],
    'anderson': ['source.py'],
}

MAILBOXES = {
    'alice': ['Salex', 'Scathy'],
    'brian': ['Salice', 'Scathy'],
    'cathy': ['Salice', 'Sbrian'],
    'david': ['Sbrian', 'Dnewhires'],
    'elise': ['Sfrank', 'Slarry'],
    'frank': ['Selise'],
    'gford': ['Sgotonote'],
    'localhost': [],
}

FOLDERNAME = {'S':'sent', 'D':'drafts', 'I':'inbox'}

COMMAND_LISTS = {
    'localhost': ['ls', 'type'],
    'hack': ['atip', 'note', 'gate'],
    'gateway': ['jump', 'ls', 'type'],
    'alice': ['ls', 'mail', 'web'],
    'brian': ['ls', 'mail', 'web'],
    'cathy': ['ls', 'mail', 'web'],
    'david': ['ls', 'mail', 'web'],
    'elise': ['ls', 'mail', 'web'],
    'frank': ['ls', 'mail', 'web'],
    'mail': ['list', 'show'],
    'hr': ['search'],
    'gford': ['ls', 'mail', 'type', 'web'],
    'anderson': ['ls', 'type'],
}

PROGRESS_TRIGGERS = {
    'type readme': [0, 'localhost'],
    'show frank': [1, 'mail'],
    'show elise': [2, 'mail'],
    'show gotonote': [3, 'mail'],
}

LOGIN_MAP = {
    'alice': 'password',
    'brian': 'baseball',
    'cathy': 'love',
    'david': 'baseball',
    'elise': 'hireme',
    'frank': '11111971',
    'anderson': 'matrix',
}

HR_MAP = {
    'elise': 'hireme',
}

HR_DATABASE = json.load(open('gamedata/hrdb.json', 'r'))

HR_FIELDS = {
    'employee': 'Employee',
    'middle': 'Middle Name',
    'last': 'Last Name',
    'type': 'Employee Type',
    'dob': 'DOB',
    'position': 'Position',
}

REPS_MAP = {'gford': 'may'}

WEBSITES = ['overnitedynamite.com', 'reusingnature.com']

def shutdown_server():
    os.kill(os.getpid(), signal.SIGINT)

class SharedMemory(object):
    def __init__(self):
        self.__lock = threading.Lock()
    def __setattr__(self, name, value):
        if name == '_SharedMemory__lock':
            self.__dict__['_SharedMemory__lock'] = value
        self.__lock.acquire()
        super(SharedMemory, self).__setattr__(name, value)
        self.__lock.release()
    def add_session(self, channel):
        sid = str(time.time())
        self.session[sid] = channel
        return sid

SHM = SharedMemory()
SHM.total_telnet = SHM.total_web = 0
SHM.sessions = {}
SHM.blocklist = []

class HackTerminal(object):
    """ This class controls the actual game itself. """
    def __init__(self, srv, channel):
        self.srv, self.c = srv, channel
        self.state = 'greeting'
        self._sys = 'localhost'
        self.prompt = '%s> ' % self._sys
        self.progress = 0
        self.route = []
        self.mukluk = False
        self.COMMAND_LISTS = deepcopy(COMMAND_LISTS)
        self.MAILBOXES = deepcopy(MAILBOXES)
        self.connect_time = datetime.isoformat(datetime.now())
        self.admin_mode = False
    @property
    def sys(self):
        return self._sys
    @sys.setter
    def sys(self, value):
        """ This doesn't work in old-style classes. """
        self.route.append(self._sys)
        self._sys = value
        self.prompt = '%s> ' % value
        if self.mukluk:
            self.prompt +='\r\n'
    def transmit(self, data):
        self.c.transmit(data)
    def push(self, data):
        self.c.set_prompt(data)
    def sendfile(self, tfile):
        self.c.sendfile(tfile)
    def echo(self, state):
        self.c.echo(state)
    def server_stats(self):
        self.transmit('****** HACKRun SERVER STATS ********')
        self.transmit('Total hackers since last boot: %s' % (SHM.total_telnet+SHM.total_web))
        self.transmit('  Web: %s  Elite Telnet: %s' % (SHM.total_web, SHM.total_telnet))
        self.transmit('Players currently hacking alone: %s' % len(SHM.sessions))
        self.transmit('************************************')
    def newmail(self, subject):
        """ This is used to append a new message in the player's mailbox. """
        self.MAILBOXES['localhost'].append('I%s' % subject)
        self.transmit('\r\n * You just received a messge from your employer.')
        self.transmit(' * Return to your localhost to view it.')
    def update_progress(self, cmdline):
        """ This is used to control game progression. """
        if cmdline in PROGRESS_TRIGGERS.keys():
            p = PROGRESS_TRIGGERS[cmdline]
            if self.progress == p[0] and self.sys == p[1]:
                self.progress +=1
                log.info('[%s] Player made progress: %s' % (self.c.opid, self.progress))
                if self.progress == 1:
                    self.COMMAND_LISTS['localhost'].append('run')
                elif self.progress == 2:
                    self.COMMAND_LISTS['localhost'].append('mail')
                    self.COMMAND_LISTS['hack'].append('hr')
                    self.newmail('hr')
                elif self.progress == 3:
                    self.COMMAND_LISTS['hack'].append('reps')
                    self.newmail('sales')
                elif self.progress == 4:
                    log.info('[%s] Player has completed demo' % self.c.opid)
                    self.transmit('*******************************************')
                    self.transmit('And this concludes the demo!')
                    self.transmit('Please stay tuned for an update in the near')
                    self.transmit('future!')
                    self.transmit('===========================================')
                    time.sleep(3)
                    self.srv.close_session(self.c.opid)
                    self.c.close()
                    return
    def show_help(self):
        """ This handy function gathers all the commands and generates a nice help menu. """
        self.transmit('%s help menu:' % self.sys)
        self.transmit(' (e)xit\texits this current system')
        self.transmit(' (h)elp\tdisplay this menu')
        for cmd in self.COMMAND_LISTS[self.sys]:
            doc = getattr(self, 'cmd_' + cmd).__doc__
            try:
                usage = getattr(self, 'cmd_' + cmd).__usage__
            except:
                usage = cmd
            self.transmit(' (%s)%s\t%s' % (usage[0], usage[1:], doc))
    def run_command(self, cmd, args):
        """ This is called from the 'shell' state to call a command the player typed in. """
        handler = getattr(self, 'cmd_%s' % cmd, None)
        if handler:
            try:
                handler(*args)
            except TypeError:
                self.transmit('Invalid number of arguments provided.')
        self.update_progress('%s %s' % (cmd, ' '.join(args)))
    def do_greeting(self, data):
        """ This is the initial game state. """
        self.sendfile('bootup')
        self.transmit('Started: %s' % datetime.strftime(datetime.now(), '%d-%b-%Y %H:%M:%S'))
        self.transmit("type 'help' for help")
        self.push('localhost> ')
        self.state = 'shell'
    def do_disconnect(self, data):
        """ This handy state was recommended by some play testers. """
        if len(data) > 0 and data[0] == 'y':
            self.srv.close_session(self.c.opid)
            self.c.close_when_done()
        else:
            self.state = 'shell'
            self.push(self.prompt)
    def do_shell(self, data):
        """ This is the 'shell' state of the game, and controls all shells. """
        p = True
        if data == 'e' or data == 'exit':
            if self.sys == 'hack':
                self.username = 'localhost'
            if self.sys == 'localhost':
                self.state = 'disconnect'
                self.push('Disconnect from localhost? ')
            else:
                self._sys = self.route.pop()
                self.prompt = '%s> ' % self._sys
        elif data == 'h' or data == 'help':
            self.show_help()
        elif data == 'STATS':
            self.server_stats()
        elif data == 'WHO':
            for opid,s in SHM.sessions.items():
                self.transmit('%s\t%s\t%s\t%s' % (opid,s.game.progress,s.game.connect_time,s.ctype))
        elif self.admin_mode and data == 'KILLALL':
            self.srv.transmit('Disconnected by server admin.')
            for s in SHM.sessions.values():
                s.close()
        elif self.admin_mode and data[:7] == 'NOTICE ':
            self.srv.transmit('BROADCAST NOTICE: %s' % data[7:])
        elif self.admin_mode and data == 'LOG':
            self.c.transmit(open('hackrun.log','r').read())
        elif self.admin_mode and data == 'IAC':
            self.state = 'iactest'
            self.push(']')
        elif self.admin_mode and data == 'MEM':
            status = open('/proc/%s/status' % os.getpid(),'r').read()
            rssi = status.index('VmRSS:')
            rss = status[rssi:status.index('\n',rssi)]
            self.transmit('%s' % rss)
        elif self.admin_mode and data == 'PID':
            self.transmit('%s' % os.getpid())
        elif self.admin_mode and data == 'SHUTDOWN':
            self.srv.transmit('Server going offline in 1 minute...')
            self.srv.halt_timer = Timer(60.0, shutdown_server)
            self.srv.halt_timer.start()
        elif hasattr(SHM, 'admin_password') and data == 'ADMIN':
            self.state = 'admin'
            self.push('HackRUN Server Admin Password: ')
            self.echo(True)
        elif data == '':
            pass
        else:
            c = data.split(' ') # Thought about using shlex, but this works fine.
            if c[0] in self.COMMAND_LISTS[self.sys]:
                self.run_command(c[0], c[1:])
            elif len(c[0]) == 1:
                for cmd in self.COMMAND_LISTS[self.sys]:
                    if c[0] == cmd[0]:
                        self.run_command(cmd, c[1:])
            else:
                self.bad_command(data)
        if self.state == 'shell' and p:
            self.push(self.prompt)
    def do_iactest(self, data):
        """ This method is used to test IAC in various clients. """
        if data == 'exit':
            self.state = 'shell'
            self.push(self.prompt)
            return
        elif data == 'x':
            self.echo(True)
        elif data == 'e':
            self.echo(False)
        self.push(']')
    def do_admin(self, data):
        """ This method takes a password and grants the user server admin access. """
        if data == SHM.admin_password:
            self.echo(False)
            self.admin_mode = True
            self.transmit('Admin access granted!')
            log.info('Granted Admin to: %s' % self.c.opid)
            self.state = 'shell'
            self.push(self.prompt)
        else:
            self.transmit('**** ACCESS DENIED ****')
            log.critical('User failed ADMIN login: %s' % self.c.opid)
            SHM.blocklist.append(self.c.opid)
            self.srv.close_session(self.c.opid)
            self.c.close()
    def do_gateway(self, data):
        """ This is the 'gateway' authentication state. """
        if self.username is None:
            self.username = data
            self.push('password: ')
            self.echo(True)
        else:
            self.echo(False)
            if self.username in LOGIN_MAP and data == LOGIN_MAP[self.username]:
                self.transmit('Successful login!')
                self.transmit('Welcome to the Gateway System')
                self.sys = 'gateway'
            else:
                self.username = None
                self.transmit("Type 'atip' for a tip")
                self.transmit('Disconnected from the gateway system')
            self.state = 'shell'
            self.push('%s> ' % self.sys)
    def do_jump(self, data):
        """ This is the 'jump' state, which takes a username and asks for a password. """
        if self.username in LOGIN_MAP and data == LOGIN_MAP[self.username]:
            self.transmit('Successful login!')
            self.transmit("Logged into %s's workstation" % self.username)
            self.sys = self.username
        else:
            self.attempts -=1
            if self.attempts == 0:
                self.transmit("Disconnected from %s's Workstation" % self.username)
            else:
                self.transmit('Invalid password')
                self.push('password: ')
                return
        self.echo(False)
        self.state = 'shell'
        self.push('%s> ' % self.sys)
    def do_hr(self, data):
        """ This is the HR System state, which connects the player to the HR Database. """
        if self.username is None:
            self.username = data
            self.push('password: ')
            self.echo(True)
        else:
            if self.username in HR_MAP and data == HR_MAP[self.username]:
                self.transmit('Welcome to the RUN Human Resources System')
                self.sys = 'hr'
                self.prompt = 'HR: '
            else:
                self.attempts -=1
                if self.attempts == 0:
                    self.transmit('Disconnected from the RUN Human Resources System')
                else:
                    self.transmit('Invalid Password')
                    self.push('password: ')
                    return
            self.echo(False)
            self.state = 'shell'
            self.push(self.prompt)
    def do_reps(self, data):
        """ This is the Reps system state, which connects the player to the Reps system. """
        if self.username is None:
            self.username = data
            self.push('password: ')
            self.echo(True)
        else:
            if self.username in REPS_MAP and data == REPS_MAP[self.username]:
                self.transmit('Successfully logged into the RUN Sales Rep System as %s' % self.username)
                self.sys = self.username
                self.prompt = '%s$ ' % self.username
            else:
                self.attempts -=1
                if self.attempts == 0:
                    self.transmit('Disconnected from the RUN Sales Rep System')
                else:
                    self.transmit('Invalid Password')
                    self.push('password: ')
                    return
            self.echo(False)
            self.state = 'shell'
            self.push(self.prompt)
    def do_hrsearch(self, data):
        """ A very simple state which does HR Database searches. """
        if data == 'exit':
            self.transmit('Exiting from the RUN HR Database')
            self.state = 'shell'
            self.push(self.prompt)
            return
        if data not in HR_DATABASE:
            self.transmit("unknown employee or associate: '%s'" % data)
        else:
            hrdata = HR_DATABASE[data]
            self.transmit(' Employee: %s' % hrdata['employee'])
            self.transmit(' Middle Name: %s' % hrdata['middle'])
            self.transmit(' Last Name: %s' % hrdata['last'])
            self.transmit(' %s' % hrdata['type'])
            self.transmit(' DOB: %s' % hrdata['dob'])
            self.transmit(' Position: %s' % hrdata['position'])
        self.push('HR.search> ')
    def bad_command(self, cmdline):
        self.transmit("unrecognized command: '%s'" % cmdline)
    def cmd_ls(self):
        """ list files in this dir """
        self.transmit('File list:')
        if self.sys not in FILE_LISTS:
            self.transmit(' no files found')
            return
        for f in FILE_LISTS[self.sys]:
            self.transmit(' %s\t1k\t-rw wwr r-x' % f)
    def cmd_type(self, tfile):
        """ type out file contents """
        if tfile in FILE_LISTS[self.sys]:
            self.sendfile('%s/%s' % (self.sys, tfile))
        else:
            self.transmit('No file: %s' % tfile)
    cmd_type.__usage__ = 'type [file]'
    def cmd_run(self):
        """ run the hack routine """
        if self.progress == 0:
            self.bad_command('run')
            return
        self.transmit('running the hack routine...')
        time.sleep(1)
        self.transmit('successfully launched')
        self.transmit("type 'help' for help")
        self.sys = 'hack'
    def cmd_atip(self):
        """ a tip on hacking """
        self.sendfile('%s/atip' % self.sys)
    def cmd_note(self):
        """ note about this routine """
        self.sendfile('%s/note' % self.sys)
    def cmd_gate(self):
        """ hack into the gateway """
        self.transmit('Establishing a connection to the Gateway System...')
        time.sleep(1)
        self.transmit('Connection Established.')
        self.transmit('Log in with your Gateway account')
        self.push('username: ')
        self.username = None
        self.state = 'gateway'
    def cmd_jump(self, username):
        """ jump to your workstation """
        self.transmit("Establishing a connection to %s's Workstation..." % username)
        time.sleep(2)
        if username not in LOGIN_MAP:
            self.transmit('No route to host.')
            return
        self.transmit('Connection Established.')
        self.transmit('Enter your Workstation password.')
        self.push('password: ')
        self.echo(True)
        self.username = username
        self.state = 'jump'
        self.attempts = 3
    cmd_jump.__usage__ = 'jump [username]'
    def cmd_mail(self):
        """ launches email program """
        self.transmit("Launching %s's mail..." % self.username)
        time.sleep(1)
        self.sys = 'mail'
        self.prompt = '%s.mail: ' % self.username
    def cmd_web(self, url):
        """ launches a web browser """
        if url.lower() not in WEBSITES:
            self.transmit('No such URL.')
            return
        self.sendfile('web/%s' % url.lower())
    cmd_web.__usage__ = 'web [url]'
    def cmd_list(self):
        """ list mail messages """
        self.transmit('List of Messages:')
        if self.username not in self.MAILBOXES:
            self.transmit(' no files found')
            return
        for f in self.MAILBOXES[self.username]:
            self.transmit(' %s\t<%s>' % (f[1:], FOLDERNAME[f[0]]))
    def cmd_show(self, message):
        """ show message details """
        self.sendfile('%s/%s/%s' % (self.sys, self.username, message))
    cmd_show.__usage__ = 'show [message]'
    def cmd_hr(self):
        """ hack into the hr system """
        self.transmit('Connecting to the RUN Human Resources System...')
        time.sleep(2)
        self.transmit('Connection established.')
        self.push('username: ')
        self.username = None
        self.state = 'hr'
        self.attempts = 3
    def cmd_search(self):
        """ search the HR database """
        self.transmit('Searching the HR employee and associate database.')
        self.transmit("Enter 'exit' to exit.")
        self.transmit('Enter username of employee or associate.')
        self.push('HR.search> ')
        self.state = 'hrsearch'
    def cmd_reps(self):
        """ hack into reps sys """
        self.transmit('Establishing a connection to the RUN Sales Rep System')
        time.sleep(1)
        self.transmit('Connection Established')
        self.transmit('Log in with your sales rep account')
        self.push('username: ')
        self.username = None
        self.state = 'reps'
        self.attempts = 3

class GameChannel(asynchat.async_chat):
    """ This is the main class which talks with the telnet client """
    def __init__(self, srv, sock=None, map=None):
        asynchat.async_chat.__init__(self, sock=sock, map=map)
        self.srv = srv
        self.set_terminator(None)
        self.ibuffer = ''
        self.game = HackTerminal(srv, self)
        self.last_seen = time.time()
        self.ctype = 'Telnet'
    def process_iac(self, iac):
        # There is little need for this server to process IAC packets.
        pass
    def collect_incoming_data(self, data):
        if self.get_terminator() is None:
            if data == '\n\n':
                # Mukluk Android MUD client fix...
                self.game.mukluk = True
                data = '\n'
                self.game.prompt +='\r\n'
            if data == '\r\n' or data == '\n':
                self.set_terminator(data)
                self.game.do_greeting(data)
                return
        if chr(255) in data:
            iac = data.index(chr(255))
            self.process_iac(data[iac:iac+3])
            if iac == 0:
                data = data[3:]
            else:
                data = data[:iac]+data[iac+3:]
        self.ibuffer += data
    def found_terminator(self):
        self.last_seen = time.time()
        data = self.ibuffer.replace(self.terminator, '')
        self.ibuffer = ''
        handler = getattr(self.game, 'do_%s' % self.game.state, None)
        if handler:
            handler(data)
    def transmit(self, data):
        self.push(data+'\r\n')
    def sendfile(self, tfile):
        self.push(open('gamedata/%s.txt' % tfile, 'r').read())
    def echo(self, state):
        if state:
            self.push(chr(255)+chr(251)+chr(1))
        else:
            self.push(chr(255)+chr(252)+chr(1))
    def set_prompt(self, data):
        self.push(data)

class WebChannel(asynchat.async_chat):
    GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    def __init__(self, srv, sock=None, map=None):
        asynchat.async_chat.__init__(self, sock=sock, map=map)
        self.srv = srv
        self.set_terminator('\r\n\r\n')
        self.ibuffer = ''
        self.state = 'handshake'
        self.ws = False
        self.game = HackTerminal(srv, self)
        self.last_ping = self.last_seen = time.time()
        self.ctype = 'Web'
    def get_payload(self, data, mask, lenth):
        payload, i = '', 0
        for b in data:
            payload += chr(ord(b) ^ ord(mask[i % 4]))
            i+=1
        return payload
    def dispatch(self, data):
        self.last_seen = time.time()
        handler = getattr(self, 'do_%s' % self.state, None)
        if handler:
            handler(data)
    def collect_incoming_data(self, data):
        if self.ws:
            hdr = (ord(data[0]) & 0x80, ord(data[0]) & 0x0F)
            #wlog.debug('FIN: %s, OP: %s' % (hdr[0], hdr[1]))
            pkt = (ord(data[1]) & 0x80, ord(data[1]) & 0x7F)
            #wlog.debug('MASK: %s, LEN: %s' % (pkt[0], pkt[1]))
            mask = data[2:6]
            if hdr[1] == 0x1:
                data = self.get_payload(data[6:], mask, pkt[1])
                self.dispatch(data)
            elif hdr[1] == 0x8:
                self.srv.close_session(self.opid)
                self.close()
            elif hdr[1] == 0x9:
                self.send_pong(data)
                self.last_ping = time.time()
            elif hdr[1] == 0xA:
                self.last_ping = time.time()
        else:
            self.ibuffer += data
        if len(self.ibuffer) > 1024:
            wlog.info('Buffer exceeded: %s' % self.opid)
            self.close()
    def found_terminator(self):
        data = self.ibuffer.replace(self.terminator, '')
        self.ibuffer = ''
        self.dispatch(data)
    def send_payload(self, data):
        hdr = ''
        if len(data) <= 125:
            hdr = chr(len(data))
        elif len(data) >= 126 and len(data) <= 65535:
            hdr = chr(126)+struct.pack("!H", len(data))
        else:
            hdr = chr(127)+struct.pack("!Q", len(data))
        self.push(chr(0x81)+hdr+data)
    def send_ping(self):
        self.push(chr(0x89)+chr(4)+'PING')
    def send_pong(self, data='PONG'):
        self.push(chr(0x8A)+chr(len(data))+data)
    def transmit(self, data):
        if self.state == 'handshake':
            self.push(data+self.terminator)
            return
        self.send_payload('M%s' % data)
    def buffer_data(self):
        if len(self.buffer_lines) < 21:
            self.send_payload('M'+''.join(self.buffer_lines))
            self.buffer_lines = None
            self.set_prompt(self.game.prompt)
            self.state = 'socket'
            self.game.state = 'shell'
            return
        self.send_payload('M'+''.join(self.buffer_lines[:20]))
        self.buffer_lines = self.buffer_lines[20:]
        self.set_prompt('--> More <--')
        self.state = 'more'
        self.game.state = 'more'
    def sendfile(self, tfile):
        self.buffer_lines = open('gamedata/%s.txt' % tfile, 'r').readlines()
        self.buffer_data()
    def parse_headers(self, headers):
        data = {}
        for line in headers:
            parts = line.split(':')
            data.update({parts[0].strip().lower():parts[1].strip()})
        return data
    def abort_on_error(self, func, *args):
        try:
            return func(*args)
        except:
            self.close()
            raise
            return False
    def get_wskey(self, key):
        import base64, hashlib # Local scope import to save overall memory.
        return base64.b64encode(hashlib.sha1(key + self.GUID).digest())
    def http_serve(self, tfile, mimetype):
        self.transmit('HTTP/1.1 200 OK')
        self.transmit('Content-Type: %s\r\n' % mimetype)
        self.transmit(open('html/%s' % tfile, 'r').read())
        self.close_when_done()
    def http_options(self):
        self.transmit('HTTP/1.1 200 OK')
        self.transmit('Content-Type: text/javascript\r\n')
        self.transmit('wsURL = "ws://%s:%s/";' % (self.srv.hostname, self.srv.port))
        self.close_when_done()
    def do_handshake(self, header):
        self.set_terminator('\r\n')
        lines = header.split('\r\n')
        request = lines[0].split(' ')
        headers = self.abort_on_error(self.parse_headers, lines[1:])
        if not headers:
            return
        if request[1] == '/' and 'sec-websocket-key' not in headers:
            return self.http_serve('terminal.html', 'text/html')
        elif request[1] == '/css':
            return self.http_serve('jquery.terminal.css', 'text/css')
        elif request[1] == '/jquery':
            return self.http_serve('jquery-1.7.2.min.js', 'application/javascript')
        elif request[1] == '/terminal':
            return self.http_serve('jquery.terminal-0.8.8.min.js', 'application/javascript')
        elif request[1] == '/options':
            return self.http_options()
        self.transmit('HTTP/1.1 101 Switching Protocols')
        self.transmit('Upgrade: WebSocket')
        self.transmit('Connection: Upgrade')
        self.transmit('Sec-WebSocket-Accept: %s\r\n' % self.get_wskey(headers['sec-websocket-key']))
        self.state = 'socket'
        self.set_terminator(None)
        self.ws = True
        SHM.total_web +=1
        if self.opid in SHM.sessions:
            self.transmit('You cannot connect twice!\r\n')
            SHM.sessions[self.opid].transmit('Connected from another location.')
            SHM.sessions[self.opid].close()
        SHM.sessions[self.opid] = self
        self.game.server_stats()
        self.sendfile('greeting')
        self.set_prompt('Press Return to accept my offer...')
    def do_socket(self, data):
        handler = getattr(self.game, 'do_%s' % self.game.state, None)
        if handler:
            handler(data)
    def do_more(self, data):
        self.buffer_data()
    def set_prompt(self, data):
        self.send_payload('P%s' % data)
    def echo(self, state):
        if state:
            self.send_payload('*')
        else:
            self.send_payload('-')

class Idler(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.finish = Event()
    def cancel(self):
        self.finish.set()
    def run(self):
        while not self.finish.is_set():
            self.finish.wait(60.0*30)
            if not self.finish.is_set():
                for s in SHM.sessions.values():
                    if not s.last_seen > time.time()-60:
                        s.transmit('Disconnecting...')
                        s.close()

class GameServer(asyncore.dispatcher):
    """ This is the main telnet server class, the class which listens for incoming connections. """
    def __init__(self, addr):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(addr)
        self.listen(5)
        log.info("Listening on port %s." % addr[1])
    def handle_accept(self):
        channel, addr = self.accept()
        SHM.total_telnet +=1
        self.clean_sessions()
        log.info("Connection from: %s" % addr[0])
        if addr[0] in SHM.blocklist:
            channel.close()
            log.info('Blocked connection from: %s' % addr[0])
            return
        c = GameChannel(self, channel)
        c.opid = addr[0]
        if addr[0] in SHM.sessions:
            c.push('You cannot connect twice!\r\n')
            SHM.sessions[addr[0]].transmit('Connected from another location.')
            SHM.sessions[addr[0]].close()
        SHM.sessions[addr[0]] = c
        c.game.server_stats()
        c.push(open('gamedata/greeting.txt','r').read())
        c.push('Press Return to accept my offer...')
    def close_session(self, opid):
        log.info("Disconnect by: %s" % opid)
        del SHM.sessions[opid]
        self.clean_sessions()
    def clean_sessions(self):
        for opid,s in SHM.sessions.items():
            if not s.connected:
                del SHM.sessions[opid]
    def transmit(self, data):
        for s in SHM.sessions.values():
            s.transmit(data)

class WebServer(asyncore.dispatcher):
    def __init__(self, addr):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(addr)
        self.listen(5)
        wlog.info("Listening on port %s." % addr[1])
        self.port = addr[1]
        self.timer = None
    def handle_accept(self):
        channel, addr = self.accept()
        self.clean_sessions()
        wlog.info("Connection from: %s" % addr[0])
        if addr[0] in SHM.blocklist:
            channel.close()
            log.info('Blocked connection from: %s' % addr[0])
            return
        c = WebChannel(self, channel)
        c.opid = addr[0]
    def close_session(self, opid):
        wlog.info("Disconnect by: %s" % opid)
        del SHM.sessions[opid]
        self.clean_sessions()
    def clean_sessions(self):
        for opid,s in SHM.sessions.items():
            if not s.connected:
                del SHM.sessions[opid]
    def transmit(self, data):
        for s in SHM.sessions.values():
            s.transmit(data)

def main():
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option('-l', '--log', dest='logfile', help='Output server log to this file.')
    parser.add_option('--hostname', dest='hostname', default='localhost', help='Sets the hostname used for the Web server.')
    parser.add_option('-p', '--port', type='int', dest='port', default=4000, help='The port to use for the Telnet server.')
    parser.add_option('--http', type='int', dest='wsport', default=8000, help='The port to use for the websockets HTTP server.')
    parser.add_option('-d', '--daemon', action='store_true', dest='daemon', default=False, help='Run server in daemon mode.')
    parser.add_option('-a', '--password', dest='admin_password', help='Sets the server admin password for special operations.')
    options, args = parser.parse_args()
    logging.basicConfig(filename=options.logfile, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.DEBUG)

    if options.daemon:
        pid = os.fork()
        if pid > 0:
            sys.stdout.write("Forked process: %d" % pid)
            sys.exit(0)
        null = open(os.devnull, 'r+')
        sys.stdout = null
        sys.stderr = null

    def handler(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, handler)
    
    if options.admin_password:
        SHM.admin_password = options.admin_password

    log.info('Hack run server started.')
    try:
        s = GameServer(('0.0.0.0', options.port))
        w = WebServer(('0.0.0.0', options.wsport))
        w.hostname = options.hostname
        idler = Idler()
        idler.start()
        asyncore.loop()
    except KeyboardInterrupt:
        idler.cancel()
        log.info('Server closed normally.')
        idler.join()

if __name__ == '__main__':
    main()
