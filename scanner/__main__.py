import datetime
import hashlib
import json
import os

import flask

from scanner.analyse import get_extractors_data, run_extractors
from scanner.utils import read_result_infos

app = flask.Flask(__name__)
app.secret_key = "super secret key"


@app.route("/", methods=["GET"])
def index():
    last_results = []
    results_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "results")
    )
    for result in os.listdir(results_dir):
        if (infos := read_result_infos(result)) is not None:
            last_results += [infos]

    print(last_results)
    return flask.render_template("index.html", last_results=last_results)


@app.route("/r/<hash>", methods=["GET"])
def result(hash):
    dst_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "results", hash)
    )
    results = {
        "infos": read_result_infos(hash),
        "extractors": get_extractors_data(dst_dir),
    }
    return flask.render_template("index.html", results=results)


@app.route("/a/<hash>")
def analyse(hash):
    infos = read_result_infos(hash)
    dst_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "results", hash)
    )
    dst_file = os.path.join(dst_dir, infos["filename"])
    run_extractors(dst_file)
    return flask.redirect(flask.url_for("result", hash=hash))


@app.route("/upload", methods=["POST"])
def upload():
    f = flask.request.files.get("file")
    hash = hashlib.sha1(f.read()).hexdigest()
    f.seek(0)
    dst_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "results", hash)
    )
    dst_file = os.path.join(dst_dir, f.filename)
    if not os.path.isdir(dst_dir):
        os.mkdir(dst_dir)
        f.save(dst_file)

    with open(os.path.join(dst_dir, "infos.json"), "wt") as fh:
        fh.write(
            json.dumps(
                {
                    "filename": f.filename,
                    "sha1": hash,
                    "last_update": datetime.datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
            )
        )

    return flask.redirect(flask.url_for("analyse", hash=hash))


def main():
    app.jinja_env.auto_reload = True
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.debug = True
    app.run()
    flask.session.clear()


if __name__ == "__main__":
    main()
