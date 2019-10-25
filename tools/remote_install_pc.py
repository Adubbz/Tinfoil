#!/usr/bin/env python
# coding: utf-8 -*-

# This is mostly the same as https://github.com/Steveice10/FBI/blob/master/servefiles/servefiles.py, with a few minor tweaks
# 1. Support for nsps was added
# 2. Support for ranged http requests was added from https://gist.github.com/shivakar/82ac5c9cb17c95500db1906600e5e1ea

import os
import socket
import struct
import sys
import threading
import time

try:
    from SimpleHTTPServer import SimpleHTTPRequestHandler
    from SocketServer import TCPServer
    from urllib import quote
    input = raw_input
except ImportError:
    from http.server import SimpleHTTPRequestHandler
    from socketserver import TCPServer
    from urllib.parse import quote


class RangeHTTPRequestHandler(SimpleHTTPRequestHandler):
    """RangeHTTPRequestHandler is a SimpleHTTPRequestHandler
    with HTTP 'Range' support"""

    def send_head(self):
        """Common code for GET and HEAD commands.
        Return value is either a file object or None
        """

        path = self.translate_path(self.path)
        ctype = self.guess_type(path)

        # Handling file location
        # If directory, let SimpleHTTPRequestHandler handle the request
        if os.path.isdir(path):
            return SimpleHTTPRequestHandler.send_head(self)

        # Handle file not found
        if not os.path.exists(path):
            return self.send_error(404, self.responses.get(404)[0])

        # Handle file request
        f = open(path, 'rb')
        fs = os.fstat(f.fileno())
        size = fs[6]

        # Parse range header
        # Range headers look like 'bytes=500-1000'
        start, end = 0, size - 1
        if 'Range' in self.headers:
            start, end = self.headers.get('Range').strip().strip('bytes=')\
                .split('-')
        if start == "":
            # If no start, then the request is for last N bytes
            # e.g. bytes=-500
            try:
                end = int(end)
            except ValueError as e:
                self.send_error(400, 'invalid range')
            start = size - end
        else:
            try:
                start = int(start)
            except ValueError as e:
                self.send_error(400, 'invalid range')
            if start >= size:
                # If requested start is greater than filesize
                self.send_error(416, self.responses.get(416)[0])
            if end == "":
                # If only start is provided then serve till end
                end = size - 1
            else:
                try:
                    end = int(end)
                except ValueError as e:
                    self.send_error(400, 'invalid range')

        # Correct the values of start and end
        start = max(start, 0)
        end = min(end, size - 1)
        self.range = (start, end)
        # Setup headers and response
        cont_length = end - start + 1
        if 'Range' in self.headers:
            self.send_response(206)
        else:
            self.send_response(200)
        self.send_header('Content-type', ctype)
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Range',
                         'bytes %s-%s/%s' % (start, end, size))
        self.send_header('Content-Length', str(cont_length))
        self.send_header('Last-Modified', self.date_time_string(fs.st_mtime))
        self.end_headers()

        return f

    def copyfile(self, infile, outfile):
        """Copies data between two file objects
        If the current request is a 'Range' request then only the requested
        bytes are copied.
        Otherwise, the entire file is copied using SimpleHTTPServer.copyfile
        """
        if 'Range' not in self.headers:
            SimpleHTTPRequestHandler.copyfile(self, infile, outfile)
            return

        start, end = self.range
        infile.seek(start)
        bufsize = 64 * 1024  # 64KB
        while True:
            buf = infile.read(bufsize)
            if not buf:
                break
            try:
                outfile.write(buf)
            except BrokenPipeError:
                pass


interactive = False


if len(sys.argv) <= 2:
    # If there aren't enough variables, use interactive mode
    if len(sys.argv) == 2:
        if sys.argv[1].lower() in ('--help', '-help', 'help', 'h', '-h', '--h'):
            print('Usage: ' + sys.argv[0] + ' <target ip> '
                  '<file / directory> [host ip] [host port]')
            sys.exit(1)

    interactive = True

elif len(sys.argv) < 3 or len(sys.argv) > 6:
    print('Usage: ' + sys.argv[0] + ' <target ip> <file / directory>'
          ' [host ip] [host port]')
    sys.exit(1)


hostPort = 8080  # Default value

if interactive:
    target_ip = input("The IP of your Switch: ")
    target_path = input("The file you want to send (.nsp, .nsz): ")

    hostIp = input("Host IP "
                   "(or press Enter to have the script detect host IP):")
    if hostIp == '':
        print('Detecting host IP...')
        hostIp = [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close())
                 for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
    else:
        hostPort = input("Host port (or press Enter to keep default, 8080):")
        if hostPort == '':
            hostPort = 8080  # Default


else:
    # (if the script is being run using a full python path; ex: "path/to/python script_name.py foo foo..")
    if sys.argv[1] == os.path.basename(__file__):
        target_ip = sys.argv[2]
        target_path = sys.argv[3]

        if len(sys.argv) >= 5:
            hostIp = sys.argv[4]
            if len(sys.argv) == 6:
                hostPort = int(sys.argv[5])
        else:
            print('Detecting host IP...')
            hostIp = [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close())
                    for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

    # (if the script is being run using just the script name and default executable for python scripts; ex: "script_name.py foo foo..")
    else:
        target_ip = sys.argv[1]
        target_path = sys.argv[2]

        if len(sys.argv) >= 4:
            hostIp = sys.argv[3]
            if len(sys.argv) == 5:
                hostPort = int(sys.argv[4])
        else:
            print('Detecting host IP...')
            hostIp = [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

target_path = target_path.strip()
if not os.path.exists(target_path):
    print(target_path + ': No such file or directory.')
    sys.exit(1)


print('Preparing data...')
baseUrl = hostIp + ':' + str(hostPort) + '/'

if os.path.isfile(target_path):
    if target_path.endswith('.nsp') or target_path.endswith('.nsz'):
        file_list_payload = baseUrl + quote(os.path.basename(target_path))
        directory = os.path.dirname(target_path)  # get file directory
    else:
        print('Unsupported file extension. Supported extensions are: .nsp, .nsz')
        sys.exit(1)

else:
    directory = target_path  # it's a directory
    file_list_payload = ''  # init the payload before adding lines
    for file in [file for file in next(os.walk(target_path))[2] if file.endswith('.nsp') or file.endswith('.nsz')]:
        file_list_payload += baseUrl + quote(file) + '\n'

if len(file_list_payload) == 0:
    print('No files to serve.')
    sys.exit(1)

file_list_payloadBytes = file_list_payload.encode('ascii')

if directory and directory != '.':  # doesn't need to move if it's already the current working directory
    os.chdir(directory)  # set working directory to the right folder to be able to serve files

print('\nURLs:')
print(file_list_payload + '\n')


class MyServer(TCPServer):
    def server_bind(self):
        import socket
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)


print('Opening HTTP server on port ' + str(hostPort))
server = MyServer(('', hostPort), RangeHTTPRequestHandler)
thread = threading.Thread(target=server.serve_forever)
thread.start()

try:
    print('Sending URL(s) to ' + target_ip + ' on port 2000...')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target_ip, 2000))
    sock.sendall(struct.pack('!L', len(file_list_payloadBytes)) + file_list_payloadBytes)
    while len(sock.recv(1)) < 1:
        time.sleep(0.05)
    sock.close()
except Exception as e:
    print('An error occurred: ' + str(e))
    server.shutdown()
    sys.exit(1)

print('Shutting down HTTP server...')
server.shutdown()
