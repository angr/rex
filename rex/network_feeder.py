
import time
import threading
import socket


class NetworkFeeder:
    """
    A class that feeds data to a socket port
    """

    def __init__(self, proto, host, port, data, is_client=True, delay=3, timeout=2):

        if not is_client:
            raise NotImplementedError("Server mode is not implemented.")

        if proto != "tcp":
            raise NotImplementedError("Only TCP mode is supported for now.")

        self._proto = proto
        self._is_client = is_client
        self._delay = delay
        self._data = data
        self._host = host
        self._port = port
        self._timeout = timeout

        t = threading.Thread(target=self.worker)
        t.start()

    def worker(self):
        if self._delay:
            time.sleep(self._delay)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if self._proto == "tcp" else socket.SOCK_DGRAM)
        sock.settimeout(self._timeout)
        sock.connect((self._host, self._port))

        sock.send(self._data)

        sock.close()
