import threading
import time
from werkzeug.serving import make_server
from flask import Flask

def create_app():
    app = Flask(__name__)
    @app.route('/')
    def index():
        return "return code: 200"
    return app


class FlaskServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.app = create_app()
        self.host = host
        self.port = port
        self._srv = make_server(self.host, self.port, self.app)
        self._thread = threading.Thread(target=self._srv.serve_forever)
        self._thread.daemon = True

    def start(self):
        self._thread.start()
        return self

    def stop(self, timeout=None):
        self._srv.shutdown()
        self._thread.join(timeout)

if __name__ == '__main__':
    server = FlaskServer()
    server.start()
    try:
        # keeps the main thread alive until asked to stop (Ctrl+C or programmatic stop)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()



# this is just for a base structure of server.py file