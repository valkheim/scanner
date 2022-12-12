import flask
import hashlib
import os

from scanner.analyse import analyse

app = flask.Flask(__name__)
app.secret_key = "super secret key"

class ChecksumCalcStream(object):
    def __init__(self, stream):
        self._stream = stream
        self._hash = hashlib.sha1()

    def read(self, bytes):
        rv = self._stream.read(bytes)
        self._hash.update(rv)
        return rv

    def readline(self, size_hint):
        rv = self._stream.readline(size_hint)
        self._hash.update(rv)
        return rv

def generate_hash(request):
    env = request.environ
    stream = ChecksumCalcStream(env['wsgi.input'])
    env['wsgi.input'] = stream
    return stream._hash


@app.route("/", methods=["GET"])
def index():
    import os
    last_results = {x:x for x in os.listdir("results")}
    return flask.render_template("index.html", last_results=last_results)

@app.route("/r/<hash>", methods=["GET"])
def result(hash):
    return flask.render_template("index.html", result=hash)

@app.route("/upload", methods=["POST"])
def upload():
    f = flask.request.files.get("file")
    # Copy file to results
    hash = generate_hash(flask.request).hexdigest()
    dst_dir = os.path.join("results", hash)
    dst_file = os.path.join(dst_dir, f.filename)
    if not os.path.isdir(dst_dir):
        os.mkdir(dst_dir)
        f.save(dst_file)

    # Analyse file
    analyse(dst_file)
    return flask.redirect(flask.url_for("result", hash=hash))

def main():
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.debug = True
    app.run()
    flask.session.clear()

if __name__ == "__main__":
    main()
