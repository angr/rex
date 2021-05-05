
import time
import threading
import socket
import logging


_l = logging.getLogger('network_feeder')


class NetworkFeeder:
    """
    A class that feeds data to a socket port
    """

    def __init__(self, proto, host, port, data, is_client=True, delay=5, timeout=2):

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

        self._threads = { }
        self._thread_ctr = 0

    def fire(self):
        # TODO: Add a lock
        thread_id = self._thread_ctr
        t = threading.Thread(target=self.worker, args=[thread_id])
        self._threads[thread_id] = t
        self._thread_ctr += 1
        t.start()

        return thread_id

    def join(self, thread_id):
        while thread_id in self._threads:
            time.sleep(0.1)

    def worker(self, thread_id):
        print("About to fire the test case...")
        if self._delay:
            time.sleep(self._delay)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if self._proto == "tcp" else socket.SOCK_DGRAM)
            sock.settimeout(self._timeout)
            sock.connect((self._host, self._port))

            sock.send(self._data)
            sock.recv(1024)

            sock.close()
        except Exception: #pylint:disable=broad-except
            _l.error("Failed to feed network data to target %s:%d.", self._host, self._port, exc_info=True)
        finally:
            # Pop the thread object
            self._threads.pop(thread_id, None)
